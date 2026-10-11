@testable import SCP
import XCTest

/// The quoted custody strings a bridge custody rejection names after
/// "this bridge accepts " and before the next ";" (`ACCEPTED_CUSTODY` in
/// crates/scp-ffi/common/src/custody_request.rs), or nil when the message
/// carries no such clause.
private func acceptedCustodyStrings(inRejection message: String) -> [String]? {
    guard let start = message.range(of: "this bridge accepts ") else { return nil }
    let clause = message[start.upperBound...].prefix { $0 != ";" }
    let parts = clause.split(separator: "\"", omittingEmptySubsequences: false)
    // Odd-indexed parts sit between a pair of quotes.
    let quoted = stride(from: 1, to: parts.count - 1, by: 2).map { String(parts[$0]) }
    return quoted.isEmpty ? nil : quoted
}

/// The error code a bridge call threw, or a description of what it did instead.
private func errorCode(_ body: () async throws -> Identity) async -> String {
    do {
        _ = try await body()
        return "created an identity"
    } catch let ScpError.Validation(_, code) {
        return code
    } catch let ScpError.Identity(_, code) {
        return code
    } catch {
        return "\(error)"
    }
}

/// `CustodyType` carries the custody request vocabulary of spec section 3.2.2,
/// and each case gets the code that section gives it through both
/// identity-create methods (`.docs/standards/sdk-common.md` §Custody request;
/// `.docs/standards/construction.md`, consequential choices are enums).
///
/// The tests run against the `testing` XCFramework (`build-xcframework.sh
/// --dev`), which admits `in_memory` and opens the encrypted key file. Tests
/// reach `in_memory` through `TestHarnessCustody.swift`, because
/// `CustodyType` has no case for it.
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

    /// Reads the accepted set from the bridge's own `SCP-VALID-7005`
    /// rejection of "platform". `CustodyType`'s cases must be exactly that
    /// set, in the same order, with no third case (spec section 3.2.2).
    func testRequestCasesAreExactlyTheBridgeAcceptedStrings() async throws {
        do {
            _ = try await scp.inner.identityCreate(custody: "platform", testingSeed: nil)
            XCTFail("the bridge accepted the custody string \"platform\"")
        } catch let ScpError.Validation(msg, code) {
            XCTAssertEqual(code, "SCP-VALID-7005")
            let accepted = try XCTUnwrap(acceptedCustodyStrings(inRejection: msg), msg)
            XCTAssertEqual(CustodyType.allCases.map(\.rawValue), accepted)
        }
        XCTAssertEqual(CustodyType.allCases, [.encryptedFile, .osKeystore])
        XCTAssertNil(CustodyType(rawValue: harnessInMemoryCustody))
    }

    func testAcceptedCustodyStringsParsesEveryQuotedString() {
        let message = "unknown custody type \"x\" — this bridge accepts custody "
            + "\"encrypted_file\" (a file) or \"os_keystore\" (a store); inject \"callback\""
        XCTAssertEqual(
            acceptedCustodyStrings(inRejection: message),
            ["encrypted_file", "os_keystore"]
        )
    }

    func testAcceptedCustodyStringsIsNilWithoutTheClause() {
        XCTAssertNil(acceptedCustodyStrings(inRejection: "custody type \"platform\" is refused"))
        XCTAssertNil(acceptedCustodyStrings(inRejection: "this bridge accepts nothing; done"))
    }

    /// Strings outside the vocabulary, including the retired `platform`,
    /// `software`, `file` and `callback`, are `SCP-VALID-7005` on both
    /// entry points.
    func testStringsOutsideTheVocabularyAreValid7005() async {
        for custody in ["platform", "software", "file", "callback", "EncryptedFile"] {
            let create = await errorCode {
                try await self.scp.inner.identityCreate(custody: custody, testingSeed: nil)
            }
            XCTAssertEqual(create, "SCP-VALID-7005", "identityCreate(\(custody))")
            let agent = await errorCode {
                try await self.scp.inner.identityCreateWithAgentKey(custody: custody)
            }
            XCTAssertEqual(agent, "SCP-VALID-7005", "identityCreateWithAgentKey(\(custody))")
        }
    }

    /// `osKeystore` needs a `KeyCustodyProvider`, which neither method takes,
    /// so both answer it with `SCP-IDENT-1003` naming the method that does.
    func testOsKeystoreWithoutAProviderIsIdent1003() async throws {
        do {
            _ = try await scp.identityCreate(custody: .osKeystore)
            XCTFail("identityCreate(.osKeystore) created an identity with no provider")
        } catch let ScpError.Identity(msg, code) {
            XCTAssertEqual(code, "SCP-IDENT-1003")
            XCTAssertTrue(msg.contains("identity_create_with_custody"), msg)
        }
        let agent = await errorCode {
            try await self.scp.identityCreateWithAgentKey(custody: .osKeystore)
        }
        XCTAssertEqual(agent, "SCP-IDENT-1003")
    }

    /// A testing seed with either `CustodyType` case is `SCP-VALID-7009`,
    /// checked before the custody value is read.
    func testSeedWithACustodyTypeCaseIsValid7009() async {
        let seed = Data(repeating: 7, count: 32)
        for custody in CustodyType.allCases {
            let code = await errorCode {
                try await self.scp.identityCreate(custody: custody, testingSeed: seed)
            }
            XCTAssertEqual(code, "SCP-VALID-7009", "\(custody)")
        }
    }

    /// The harness's raw `in_memory` string creates an identity through both
    /// bridge methods on the testing build, and the handle reports the
    /// request value. The same seed yields the same verifying key, so the
    /// helper passes the seed through.
    func testHarnessInMemoryCreatesAnIdentity() async throws {
        let identity = try await createInMemoryIdentity(scp)
        XCTAssertEqual(identity.custodyType(), "in_memory")
        XCTAssertFalse(identity.verifyingKey()?.isEmpty ?? true)
        let agent = try await createInMemoryIdentityWithAgentKey(scp)
        XCTAssertEqual(agent.custodyType(), "in_memory")

        let seed = Data(repeating: 9, count: 32)
        let first = try await createInMemoryIdentity(scp, seed: seed)
        let other = try SCP(storage: .inMemory)
        let second = try await createInMemoryIdentity(other, seed: seed)
        try await other.shutdown(timeoutMillis: 1000)
        XCTAssertEqual(first.verifyingKey(), second.verifyingKey())
        XCTAssertNotNil(first.verifyingKey())
    }

    /// `encryptedFile` opens `$HOME/.scp/keys.bin` under `SCP_KEY_PASSPHRASE`
    /// through both methods, and the handle reports the request value. A
    /// missing passphrase is `SCP-VALID-7001`, and a key file sealed under
    /// another passphrase is `SCP-IDENT-1008`. XCTest runs these methods
    /// serially, and the variables are restored before the method returns.
    func testEncryptedFileCreatesAnIdentityAndRejectsBadInputs() async throws {
        let fileManager = FileManager.default
        let base = fileManager.temporaryDirectory
            .appendingPathComponent("scp-custody-\(UUID().uuidString)")
        let createHome = base.appendingPathComponent("create")
        let agentHome = base.appendingPathComponent("agent")
        let savedHome = getenv("HOME").map { String(cString: $0) }
        let savedPassphrase = getenv("SCP_KEY_PASSPHRASE").map { String(cString: $0) }
        defer {
            if let savedHome {
                setenv("HOME", savedHome, 1)
            } else {
                unsetenv("HOME")
            }
            if let savedPassphrase {
                setenv("SCP_KEY_PASSPHRASE", savedPassphrase, 1)
            } else {
                unsetenv("SCP_KEY_PASSPHRASE")
            }
            try? fileManager.removeItem(at: base)
        }

        setenv("SCP_KEY_PASSPHRASE", "swift-encrypted-file-passphrase", 1)
        setenv("HOME", createHome.path, 1)
        let identity = try await scp.identityCreate(custody: .encryptedFile)
        XCTAssertEqual(identity.custodyType(), "encrypted_file")
        XCTAssertTrue(identity.did().hasPrefix("did:dht:"))
        let keyFile = createHome.appendingPathComponent(".scp/keys.bin")
        XCTAssertTrue(fileManager.fileExists(atPath: keyFile.path), keyFile.path)

        setenv("HOME", agentHome.path, 1)
        let agent = try await scp.identityCreateWithAgentKey(custody: .encryptedFile)
        XCTAssertEqual(agent.custodyType(), "encrypted_file")

        setenv("HOME", createHome.path, 1)
        setenv("SCP_KEY_PASSPHRASE", "another-passphrase", 1)
        let wrongPassphrase = await errorCode {
            try await self.scp.identityCreate(custody: .encryptedFile)
        }
        XCTAssertEqual(wrongPassphrase, "SCP-IDENT-1008")

        unsetenv("SCP_KEY_PASSPHRASE")
        let noPassphrase = await errorCode {
            try await self.scp.identityCreateWithAgentKey(custody: .encryptedFile)
        }
        XCTAssertEqual(noPassphrase, "SCP-VALID-7001")
    }
}
