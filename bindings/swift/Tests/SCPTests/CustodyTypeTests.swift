@testable import SCP
import XCTest

/// Two halves of one contract: `CustodyType` carries the two values the custody
/// vocabulary states, and a value that reaches no key store comes back to the
/// caller as a typed error rather than as a weaker key store.
///
/// Section 3.2.2 of the identity spec, "The Custody Vocabulary", states that a
/// caller "names exactly one of two custody values", that "The vocabulary holds
/// no third value, and a shipped build answers every other string with a typed
/// error", and that a bridge answering `"os_keystore"` without a platform
/// key-custody callback "returns a typed error" and "does not fall back to
/// `encrypted_file`, and it does not fall back to an in-memory store".
///
/// `build_key_custody` in `crates/scp-ffi/uniffi/src/bridge.rs` answers
/// every string outside the vocabulary with `SCP-VALID-7005`, and that includes
/// the five retired spellings section 3.2.2 names: `"platform"`, `"software"`,
/// `"file"`, `"platform_managed"`, and `"hardware"`.
///
/// The enum tests need no native binary. The bridge tests call the compiled
/// UniFFI cdylib through the real `SCP` class, so each one exercises the
/// rejection path rather than constructing an `ScpError` by hand.
///
/// `SCP.identityCreate` takes a `CustodyType`, so no caller of the SDK can name
/// a custody value the vocabulary does not state. The tests that pass a retired
/// spelling reach past that signature to the UniFFI `Scp` object `SCP` holds in
/// `inner`, because the bridge still screens every string it receives and these
/// tests pin the code it answers each one with.
///
/// ## Provenance
///
/// - Section 3.2.2 of the identity spec, "The Custody Vocabulary"
/// - ADR-006 (platform abstraction and the `KeyCustodyProvider` callback)
final class CustodyTypeTests: XCTestCase {
    /// The code the bridge raises for `"os_keystore"` when the caller supplied
    /// no platform key-custody callback.
    private static let custodyProviderRequiredCode = "SCP-IDENT-1003"
    /// The code the bridge raises for a custody string outside the vocabulary.
    private static let unrecognizedCustodyCode = "SCP-VALID-7005"
    /// The five spellings section 3.2.2 names and states "name no custody
    /// backend".
    private static let retiredSpellings = [
        "platform",
        "software",
        "file",
        "platform_managed",
        "hardware"
    ]

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

    /// Asserts `body` throws `ScpError.Validation` carrying `expectedCode`.
    private func assertValidationCode<T>(
        _ expectedCode: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> T
    ) async {
        do {
            _ = try await body()
            XCTFail("expected ScpError.Validation(\(expectedCode)) to be thrown", file: file, line: line)
        } catch let ScpError.Validation(_, code) {
            XCTAssertEqual(code, expectedCode, "unexpected validation code", file: file, line: line)
        } catch {
            XCTFail("expected ScpError.Validation, got \(error)", file: file, line: line)
        }
    }

    // MARK: - The custody values the enum carries

    /// `CustodyType` carries the two values section 3.2.2 states and no other.
    ///
    /// A case added without a matching arm in `build_key_custody` would
    /// offer a string the bridge answers with `SCP-VALID-7005` instead of the
    /// code this enum's documentation promises. `"in_memory"` is absent by
    /// design: section 3.2.2 states that the string is a test-harness
    /// affordance and that "no SDK enum spells it".
    func testCustodyTypeCarriesTheTwoValuesTheVocabularyStates() {
        XCTAssertEqual(CustodyType.allCases.map(\.rawValue), ["encrypted_file", "os_keystore"])
        XCTAssertEqual(CustodyType.encryptedFile.rawValue, "encrypted_file")
        XCTAssertEqual(CustodyType.osKeystore.rawValue, "os_keystore")
    }

    /// Each spelling parses back to its case, so a caller who reads a custody
    /// value off the wire lands on the case whose documentation describes it.
    /// Every retired spelling parses to nothing.
    func testCustodyTypeParsesEachSpellingBackToItsCase() {
        XCTAssertEqual(CustodyType(rawValue: "encrypted_file"), .encryptedFile)
        XCTAssertEqual(CustodyType(rawValue: "os_keystore"), .osKeystore)
        XCTAssertNil(CustodyType(rawValue: "in_memory"))
        XCTAssertNil(CustodyType(rawValue: "magic"))
        for retired in Self.retiredSpellings {
            XCTAssertNil(CustodyType(rawValue: retired), "\(retired) must parse to no case")
        }
    }

    /// The test-harness custody string mints a real `did:dht` identity, which
    /// is what section 3.2.2 states a `testing` build accepts it for.
    func testTheTestHarnessCustodyStringCreatesAnIdentity() async throws {
        let identity = try await scp.identityCreateInTestHarnessCustody()
        XCTAssertTrue(
            identity.did().hasPrefix("did:dht:"),
            "the test-harness custody string must mint a did:dht identity"
        )
    }

    // MARK: - The custody values that reach no key store

    /// `osKeystore` fails closed: `identityCreate` supplies no platform
    /// key-custody callback, so the bridge builds no key store and reports
    /// `SCP-IDENT-1003` rather than falling back to a weaker one.
    func testOsKeystoreWithoutAProviderFailsClosed() async {
        await assertIdentityCode(Self.custodyProviderRequiredCode) {
            try await self.scp.identityCreate(custody: .osKeystore)
        }
    }

    /// The agent-key creation path rejects `osKeystore` too, so neither
    /// creation path falls back to a different key store.
    func testCreateWithAgentKeyRejectsOsKeystoreWithoutAProvider() async {
        await assertIdentityCode(Self.custodyProviderRequiredCode) {
            try await self.scp.identityCreateWithAgentKey(custody: .osKeystore)
        }
    }

    /// Each retired spelling draws the validation code, not the identity code,
    /// so the two rejections stay distinguishable.
    ///
    /// `"platform"` and `"file"` each built a key store at some point in this
    /// bridge's history, so the SDK named one substrate and delivered another.
    /// `CustodyType` spells neither, so this test sends each string to the
    /// UniFFI `Scp` object directly.
    func testEveryRetiredSpellingDrawsTheValidationCode() async {
        for retired in Self.retiredSpellings {
            await assertValidationCode(Self.unrecognizedCustodyCode) {
                try await self.scp.inner.identityCreate(custody: retired, testingSeed: nil)
            }
        }
    }

    /// A custody string outside the vocabulary and outside the retired set
    /// draws the same validation code.
    func testUnrecognizedCustodyStringDrawsValidationCode() async {
        await assertValidationCode(Self.unrecognizedCustodyCode) {
            try await self.scp.inner.identityCreate(custody: "magic", testingSeed: nil)
        }
    }

    // MARK: - What a DID document publishes about custody

    /// The published value comes off the running backend, not off the value the
    /// caller named.
    ///
    /// Section 3.2.2 states that the published value "is derived, never
    /// declared". The in-memory key store holds every private key in a
    /// process-memory map that nothing gates, which is a pair the published
    /// vocabulary states no value for, so the bridge publishes nothing.
    /// ADR-039's Enforcement Stack layer 4 gives that absence a meaning,
    /// "Absence of attestation is itself a signal".
    func testPublishedCustodyReadsTheRunningBackend() async throws {
        let identity = try await scp.identityCreateInTestHarnessCustody()
        let published = try await scp.identityPublishedCustody(did: identity.did())
        XCTAssertNil(published, "an unstatable pair publishes no custody value")
    }

    /// A DID this instance retains no custody for draws `SCP-IDENT-1017`.
    ///
    /// The published value comes off the running backend, so an instance
    /// holding no backend for a DID reports a typed error rather than a value
    /// it reconstructed from the DID string.
    func testPublishedCustodyFailsClosedForAnUnretainedDid() async {
        await assertIdentityCode("SCP-IDENT-1017") {
            try await self.scp.identityPublishedCustody(did: "did:dht:z6MkNotRegistered")
        }
    }
}
