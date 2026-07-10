@testable import SCP
import XCTest

/// Tests for pure-Swift convenience types in `Types.swift`.
///
/// These tests do NOT require the native UniFFI binary — the capability string
/// helpers are pure Swift string construction.
final class TypesTests: XCTestCase {
    func testCanonicalCapabilityNames() {
        XCTAssertEqual(Capability.Name.messagesRead, "messages:read")
        XCTAssertEqual(Capability.Name.messagesWrite, "messages:write")
        XCTAssertEqual(Capability.Name.outletQueryAll, "outlet:query:*")
        XCTAssertEqual(Capability.Name.outletCallAll, "outlet:call:*")
        XCTAssertEqual(Capability.Name.outletRegister, "outlet:register")
        XCTAssertEqual(Capability.Name.outletInterface, "outlet:interface")
    }

    func testOutletCallCapabilityString() {
        XCTAssertEqual(Capability.outletCall("calculator"), "outlet:call:calculator")
    }

    func testOutletQueryCapabilityString() {
        XCTAssertEqual(Capability.outletQuery("calculator"), "outlet:query:calculator")
    }
}
