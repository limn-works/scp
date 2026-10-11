@testable import SCP
import XCTest

/// The quoted custody strings a bridge custody rejection names after
/// "this bridge accepts " and before the next ";" (`ACCEPTED_CUSTODY` in
/// crates/scp-ffi/uniffi/src/bridge.rs), or nil when the message carries no
/// such clause.
private func acceptedCustodyStrings(inRejection message: String) -> [String]? {
    guard let start = message.range(of: "this bridge accepts ") else { return nil }
    let clause = message[start.upperBound...].prefix { $0 != ";" }
    let parts = clause.split(separator: "\"", omittingEmptySubsequences: false)
    // Odd-indexed parts sit between a pair of quotes.
    let quoted = stride(from: 1, to: parts.count - 1, by: 2).map { String(parts[$0]) }
    return quoted.isEmpty ? nil : quoted
}

/// `CustodyType` carries exactly the custody strings the UniFFI bridge accepts,
/// and each case reaches a key store through both identity-create methods
/// (SCP-294; `.docs/standards/construction.md`, consequential choices are
/// enums).
final class CustodyTypeTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs.
    // swiftlint:disable:next implicitly_unwrapped_optional
    var scp: SCP!

    override func setUpWithError() throws {
        try super.setUpWithError()
        scp = try SCP(storage: .inMemory)
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    /// Reads the accepted set from the bridge's own `SCP-IDENT-1003` rejection
    /// of "platform". A case the bridge does not accept fails this test, and
    /// so does a bridge string with no case.
    func testCasesAreExactlyTheBridgeAcceptedStrings() async throws {
        do {
            _ = try await scp.inner.identityCreate(custody: "platform", testingSeed: nil)
            XCTFail("the bridge accepted the custody string \"platform\"")
        } catch let ScpError.Identity(msg, code) {
            XCTAssertEqual(code, "SCP-IDENT-1003")
            let accepted = try XCTUnwrap(acceptedCustodyStrings(inRejection: msg), msg)
            XCTAssertEqual(CustodyType.allCases.map(\.rawValue), accepted)
        }
    }

    func testAcceptedCustodyStringsParsesEveryQuotedString() {
        let message = "custody type \"x\" names no key store — this bridge accepts "
            + "\"in_memory\" or \"file\" only here; inject \"callback\""
        XCTAssertEqual(acceptedCustodyStrings(inRejection: message), ["in_memory", "file"])
    }

    func testAcceptedCustodyStringsIsNilWithoutTheClause() {
        XCTAssertNil(acceptedCustodyStrings(inRejection: "custody type \"platform\" is refused"))
        XCTAssertNil(acceptedCustodyStrings(inRejection: "this bridge accepts nothing; done"))
    }

    /// Every case creates an identity through `identityCreate(custody:)`. A
    /// case the bridge refuses throws here (`SCP-IDENT-1003` for `platform`).
    func testEveryCaseCreatesAnIdentity() async throws {
        for custody in CustodyType.allCases {
            let identity = try await scp.identityCreate(custody: custody)
            XCTAssertFalse(identity.verifyingKey()?.isEmpty ?? true, "\(custody) holds no key")
        }
    }

    /// Every case creates an identity through
    /// `identityCreateWithAgentKey(custody:)`.
    func testEveryCaseCreatesAnIdentityWithAgentKey() async throws {
        for custody in CustodyType.allCases {
            let identity = try await scp.identityCreateWithAgentKey(custody: custody)
            XCTAssertFalse(identity.verifyingKey()?.isEmpty ?? true, "\(custody) holds no key")
        }
    }
}
