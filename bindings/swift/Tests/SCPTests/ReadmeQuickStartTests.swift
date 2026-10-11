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
/// Both examples use `CustodyType.inMemory`, which only an XCFramework built with
/// the `testing` feature accepts (`build-xcframework.sh --dev`, which CI uses).
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

    func testReadmeQuickStartRuns() async throws {
        try await runQuickStart()
    }

    /// The README function returns a code only from its `catch ScpError.Context`
    /// clause, and any other error propagates, so an `SCP-CTX-` code proves that
    /// clause caught the send to a closed context.
    func testReadmeErrorHandlingCatchesTheContextError() async throws {
        let scp = try SCP(storage: .inMemory)
        let identity = try await scp.identityCreate(custody: .inMemory)
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
                consequenceConfigJson: nil
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
