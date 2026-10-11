@testable import SCP
import XCTest

/// The custody strings `parse_custody_method` in
/// crates/scp-ffi/uniffi/src/bridge.rs builds a key store for. Listed as
/// literals so the test reads the bridge's accepted set, not the enum under
/// test.
private let bridgeAcceptedCustodyStrings = ["in_memory"]

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

    /// A case the bridge does not accept, such as `platform` or `software`,
    /// fails this test, and so does a bridge string with no case.
    func testCasesAreExactlyTheBridgeAcceptedStrings() {
        XCTAssertEqual(CustodyType.allCases.map(\.rawValue), bridgeAcceptedCustodyStrings)
    }

    /// Every case creates an identity through `identityCreate(custody:)`. A
    /// case the bridge refuses throws here (`SCP-IDENT-1003` for `platform`).
    func testEveryCaseCreatesAnIdentity() async throws {
        for custody in CustodyType.allCases {
            let identity = try await scp.identityCreate(custody: custody)
            XCTAssertTrue(identity.did().hasPrefix("did:"), "\(custody) created no DID")
        }
    }

    /// Every case creates an identity through
    /// `identityCreateWithAgentKey(custody:)`.
    func testEveryCaseCreatesAnIdentityWithAgentKey() async throws {
        for custody in CustodyType.allCases {
            let identity = try await scp.identityCreateWithAgentKey(custody: custody)
            XCTAssertTrue(identity.did().hasPrefix("did:"), "\(custody) created no DID")
        }
    }
}
