@testable import SCP
import XCTest

/// Two halves of one contract: `CustodyType` spells every custody string the
/// UniFFI bridge names, and a string that reaches no key store comes back to
/// the caller as a typed error rather than as a weaker key store.
///
/// `parse_custody_method` in `crates/scp-ffi/uniffi/src/bridge.rs` builds a key
/// store for `"in_memory"` and for no other string. It answers `"platform"`
/// and `"software"` with `SCP-IDENT-1003` in every build, because neither
/// string reaches Apple Keychain — a caller reaches Keychain by injecting a
/// `KeyCustodyProvider` through `identityCreateWithCustody`. Every string the
/// enum does not carry draws `SCP-VALID-7005`.
///
/// Before SCP-294, the custody-string and identity-parameter story, the
/// `platform` case's doc comment named four platform key stores and called the
/// case the default. The case reaches none of those four key stores, so these
/// tests hold the enum's documented behaviour against the bridge's actual
/// behaviour.
///
/// The enum tests need no native binary. The bridge tests call the compiled
/// UniFFI cdylib through the real `SCP` class, so each one exercises the
/// rejection path rather than constructing an `ScpError` by hand.
///
/// ## Provenance
///
/// - Spec section 3.2 (Key Custody)
/// - ADR-006 (platform abstraction and the `KeyCustodyProvider` callback)
final class CustodyTypeTests: XCTestCase {
    /// The code the bridge raises for a custody string that names a key store
    /// only a `KeyCustodyProvider` reaches.
    private static let custodyProviderRequiredCode = "SCP-IDENT-1003"
    /// The code the bridge raises for a custody string it does not recognize.
    private static let unrecognizedCustodyCode = "SCP-VALID-7005"

    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs — the XCTest lifecycle guarantees non-nil.
    // swiftlint:disable:next implicitly_unwrapped_optional
    private var scp: SCP!

    override func setUpWithError() throws {
        try super.setUpWithError()
        scp = try SCP(storage: .inMemory)
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    // MARK: - Helpers

    /// Asserts `body` throws `ScpError.Identity` carrying `expectedCode`.
    private func assertIdentityCode<T>(
        _ expectedCode: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> T
    ) async {
        do {
            _ = try await body()
            XCTFail("expected ScpError.Identity(\(expectedCode)) to be thrown", file: file, line: line)
        } catch let ScpError.Identity(_, code) {
            XCTAssertEqual(code, expectedCode, "unexpected identity code", file: file, line: line)
        } catch {
            XCTFail("expected ScpError.Identity, got \(error)", file: file, line: line)
        }
    }

    // MARK: - The custody strings the enum carries

    /// Every `CustodyType` case spells a custody string `parse_custody_method`
    /// names in a match arm. Pin the whole set, because a case added without a
    /// matching arm there would offer a string the bridge answers with
    /// `SCP-VALID-7005` instead of the code this enum's documentation promises.
    func testCustodyTypeSpellsEveryStringTheBridgeNames() {
        XCTAssertEqual(CustodyType.allCases.map(\.rawValue), ["in_memory", "platform", "software"])
        XCTAssertEqual(CustodyType.inMemory.rawValue, "in_memory")
        XCTAssertEqual(CustodyType.platform.rawValue, "platform")
        XCTAssertEqual(CustodyType.software.rawValue, "software")
    }

    /// Each spelling parses back to its case, so a caller who reads a custody
    /// string off the wire lands on the case whose documentation describes it.
    func testCustodyTypeParsesEachSpellingBackToItsCase() {
        XCTAssertEqual(CustodyType(rawValue: "in_memory"), .inMemory)
        XCTAssertEqual(CustodyType(rawValue: "platform"), .platform)
        XCTAssertEqual(CustodyType(rawValue: "software"), .software)
        XCTAssertNil(CustodyType(rawValue: "magic"))
    }

    /// The one case that reaches a key store mints a real `did:dht` identity.
    func testInMemoryCustodyStringCreatesAnIdentity() async throws {
        let identity = try await scp.identityCreate(custody: CustodyType.inMemory.rawValue)
        XCTAssertTrue(identity.did().hasPrefix("did:dht:"), "the accepted custody string must mint a did:dht identity")
    }

    // MARK: - The custody strings that reach no key store

    /// `platform` fails closed: the bridge builds no key store and reports
    /// `SCP-IDENT-1003`.
    func testPlatformCustodyStringFailsClosed() async {
        await assertIdentityCode(Self.custodyProviderRequiredCode) {
            try await self.scp.identityCreate(custody: CustodyType.platform.rawValue)
        }
    }

    /// `software` fails closed for the same reason and with the same code.
    func testSoftwareCustodyStringFailsClosed() async {
        await assertIdentityCode(Self.custodyProviderRequiredCode) {
            try await self.scp.identityCreate(custody: CustodyType.software.rawValue)
        }
    }

    /// The agent-key creation path rejects `platform` too, so neither creation
    /// path falls back to a different key store.
    func testCreateWithAgentKeyRejectsPlatformCustodyString() async {
        await assertIdentityCode(Self.custodyProviderRequiredCode) {
            try await self.scp.identityCreateWithAgentKey(custody: CustodyType.platform.rawValue)
        }
    }

    /// A custody string the enum does not carry draws the validation code, not
    /// the identity code, so the two rejections stay distinguishable.
    func testUnrecognizedCustodyStringDrawsValidationCode() async {
        do {
            _ = try await scp.identityCreate(custody: "magic")
            XCTFail("expected ScpError.Validation(\(Self.unrecognizedCustodyCode)) to be thrown")
        } catch let ScpError.Validation(_, code) {
            XCTAssertEqual(code, Self.unrecognizedCustodyCode, "unexpected validation code")
        } catch {
            XCTFail("expected ScpError.Validation, got \(error)")
        }
    }
}
