import Foundation
import SCP
import XCTest

/// Proves that the code examples in `bindings/swift/README.md` compile and run.
///
/// Swift cannot compile a README block at test time, so `ReadmeQuickStart.swift`
/// and `ReadmeErrorHandling.swift` in this test target hold copies that the test
/// target compiles. The copy tests fail when a copy and its README block differ,
/// and the run tests call each copy. Together they turn an edit that breaks a
/// README block red: the edit either diverges from the copy or, applied to both,
/// stops compiling or misbehaves.
///
/// The quick start uses `CustodyType.encryptedFile`, which only an XCFramework
/// built with the `testing` feature serves (`build-xcframework.sh --dev`, which
/// CI uses; a release build throws `SCP-IDENT-1100`). Its run test points `HOME`
/// at a scratch directory, sets `SCP_KEY_PASSPHRASE`, and checks that the key
/// file lands there. The error-handling test creates its identity through
/// `TestHarnessCustody.swift`.
final class ReadmeQuickStartTests: XCTestCase {
    private static let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

    /// Returns the first `swift` block under the README's `## <heading>` line.
    static func readmeBlock(_ readme: String, heading: String) throws -> String {
        let afterHeading = try XCTUnwrap(
            readme.components(separatedBy: "\n## \(heading)\n").dropFirst().first,
            "the README has no '## \(heading)' heading"
        )
        let body = try XCTUnwrap(
            afterHeading.components(separatedBy: "```swift\n").dropFirst().first,
            "the \(heading) section has no swift block"
        )
        let block = try XCTUnwrap(
            body.components(separatedBy: "\n```\n").first,
            "the \(heading) swift block has no closing fence"
        )
        return block + "\n"
    }

    /// Returns a copy file without its leading comment header.
    static func copyBody(_ source: String) -> String {
        var lines = source.components(separatedBy: "\n")[...]
        while let first = lines.first, first.hasPrefix("//") || first.isEmpty {
            lines = lines.dropFirst()
        }
        return lines.joined(separator: "\n")
    }

    private func assertCopyMatchesReadme(copyFile: String, heading: String) throws {
        let readme = try String(
            contentsOf: Self.testsDirectory.appendingPathComponent("../../README.md").standardized,
            encoding: .utf8
        )
        let copy = try String(
            contentsOf: Self.testsDirectory.appendingPathComponent(copyFile),
            encoding: .utf8
        )
        XCTAssertEqual(
            Self.copyBody(copy),
            try Self.readmeBlock(readme, heading: heading),
            "Tests/SCPTests/\(copyFile) must match the README \(heading) block byte for byte"
        )
    }

    func testReadmeBlockExtractionReadsTheBlockUnderTheHeading() throws {
        let text = "# T\n\n```swift\nbefore()\n```\n\n### Quick Start\n\n```swift\nh3()\n```\n\n"
            + "## Quick Start\n\nProse.\n\n```swift\nquick()\n```\n\n```swift\nafter()\n```\n"
        XCTAssertEqual(try Self.readmeBlock(text, heading: "Quick Start"), "quick()\n")
    }

    func testCopyMatchesTheReadmeBlock() throws {
        try assertCopyMatchesReadme(copyFile: "ReadmeQuickStart.swift", heading: "Quick Start")
    }

    func testErrorHandlingCopyMatchesTheReadmeBlock() throws {
        try assertCopyMatchesReadme(copyFile: "ReadmeErrorHandling.swift", heading: "Error Handling")
    }

    /// XCTest runs these methods serially, and the variables are restored
    /// before the method returns.
    func testReadmeQuickStartRuns() async throws {
        let fileManager = FileManager.default
        let home = fileManager.temporaryDirectory
            .appendingPathComponent("scp-readme-\(UUID().uuidString)")
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
            try? fileManager.removeItem(at: home)
        }
        setenv("HOME", home.path, 1)
        setenv("SCP_KEY_PASSPHRASE", "readme-quickstart-test-passphrase", 1)

        try await runQuickStart()

        let keyFile = home.appendingPathComponent(".scp/keys.bin")
        XCTAssertTrue(fileManager.fileExists(atPath: keyFile.path), keyFile.path)
    }

    /// The README function returns a code only from its `catch ScpError.Context`
    /// clause, and any other error propagates, so an `SCP-CTX-` code proves that
    /// clause caught the send to a closed context.
    func testReadmeErrorHandlingCatchesTheContextError() async throws {
        let scp = try SCP(storage: .inMemory)
        let identity = try await createInMemoryIdentity(scp)
        let ctx = try await scp.contextCreate(
            identity: identity,
            params: ContextParams(
                mode: .encrypted,
                ceiling: ["messages:read", "messages:write", "context:close"],
                ceilingPolicy: .immutable,
                governance: .singleAdmin,
                memoryScope: .ephemeral,
                ttlSeconds: 3600,
                promotable: false,
                minProtocolVersion: 0,
                maxChainDepth: nil,
                maxNestingDepth: nil,
                sessionCap: nil,
                economicPolicy: nil,
                consequenceRulesJson: nil,
                consequenceConfigJson: nil,
                capabilityRequirementsJson: nil,
                pseudonymRotation: nil
            )
        )
        try await scp.contextClose(handle: ctx, identity: identity)

        let code = try await sendReportingRejection(
            scp: scp, ctx: ctx, identity: identity, payload: Data("late".utf8)
        )

        let rejected = try XCTUnwrap(code, "a send to a closed context succeeded")
        XCTAssertTrue(rejected.hasPrefix("SCP-CTX-"), "unexpected code \(rejected)")
        try await scp.shutdown()
    }
}
