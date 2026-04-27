// SCP-OUT-041d — Swift SDK unit tests for OutletError.new options-object
// form, the bridge-wire envelope parser, and labeled-arg ergonomics.

import XCTest

@testable import SCP

final class OutletErrorTests: XCTestCase {

    func testNewLabeledArgsConstructsAuthorization() throws {
        let key = try CatalogKey.make("authorization.denied")
        let err = try OutletError.new(
            outletId: "outlet-test",
            catalogKey: key,
            class: .authorization
        )
        switch err {
        case .authorization(let envelope):
            XCTAssertEqual(envelope.classWire, .authorization)
            XCTAssertEqual(envelope.slug, "authorization.denied")
        default:
            XCTFail("expected .authorization case, got \(err)")
        }
    }

    func testNewRejectsInvalidCatalogKey() {
        XCTAssertThrowsError(try CatalogKey.make("INVALID UPPER"))
    }

    func testFromBridgeWireParsesSnakeCaseFields() throws {
        let json = """
        {"code":"SCP-TOOL-6110","slug":"authorization.denied","class":"authorization","message":"\(String(repeating: "00", count: 32))","retry":{"policy":"never"},"pad_nonce":"\(String(repeating: "11", count: 16))","registration_event_id":"\(String(repeating: "22", count: 32))","source_chain":[]}
        """
        let envelope = try OutletEnvelope.fromBridgeWire(json)
        XCTAssertEqual(envelope.classWire, .authorization)
        XCTAssertEqual(envelope.code, "SCP-TOOL-6110")
        XCTAssertEqual(envelope.padNonce?.count, 16)
        XCTAssertEqual(envelope.registrationEventId?.count, 32)
    }

    func testRetryPolicyWireForm() {
        XCTAssertEqual(RetryPolicy.never.wireForm, "never")
        XCTAssertEqual(RetryPolicy.immediate.wireForm, "immediate")
        XCTAssertEqual(RetryPolicy.after(delayMs: 100).wireForm, "after")
        XCTAssertEqual(RetryPolicy.withBackoff(minMs: 1, maxMs: 2).wireForm, "with-backoff")
    }
}
