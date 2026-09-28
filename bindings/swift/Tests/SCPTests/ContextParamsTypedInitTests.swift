@testable import SCP
import XCTest

/// Tests that the typed ``ContextParams`` initializer forwards the ceiling the
/// caller declared, including an absent one.
///
/// The bridge reads `ceiling == nil` as "no ceiling declared" and records
/// `default_ceiling()`, and it records `[]` as a ceiling that grants nothing.
/// An initializer that took a non-optional `[String]` forwarded every call as
/// a declared list, so a Swift caller on the typed path could not ask for the
/// default ceiling.
final class ContextParamsTypedInitTests: XCTestCase {
    private func makeParams(ceiling: [String]?) throws -> ContextParams {
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

    func testAbsentCeilingStaysAbsent() throws {
        XCTAssertNil(try makeParams(ceiling: nil).ceiling)
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
