import Foundation
import XCTest

/// Proves that the quick start in `bindings/swift/README.md` compiles and runs.
///
/// Swift cannot compile a README block at test time, so `ReadmeQuickStart.swift`
/// in this test target holds a copy that the test target compiles. The first
/// test fails when that copy and the README block differ, and the second runs
/// the copy. Together they turn an edit that breaks the README block red: the
/// edit either diverges from the copy or, applied to both, stops compiling or
/// throws.
///
/// The block uses `CustodyType.inMemory`, which only an XCFramework built with
/// the `testing` feature accepts (`build-xcframework.sh --dev`, which CI uses).
final class ReadmeQuickStartTests: XCTestCase {
    private static let testsDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()

    /// Returns the first `swift` block under the README's `## Quick Start` heading.
    static func readmeBlock(_ readme: String) throws -> String {
        let afterHeading = try XCTUnwrap(
            readme.components(separatedBy: "\n## Quick Start\n").dropFirst().first,
            "the README has no '## Quick Start' heading"
        )
        let body = try XCTUnwrap(
            afterHeading.components(separatedBy: "```swift\n").dropFirst().first,
            "the Quick Start section has no swift block"
        )
        let block = try XCTUnwrap(
            body.components(separatedBy: "\n```\n").first,
            "the Quick Start swift block has no closing fence"
        )
        return block + "\n"
    }

    /// Returns `ReadmeQuickStart.swift` without its leading comment header.
    static func copyBody(_ source: String) -> String {
        var lines = source.components(separatedBy: "\n")[...]
        while let first = lines.first, first.hasPrefix("//") || first.isEmpty {
            lines = lines.dropFirst()
        }
        return lines.joined(separator: "\n")
    }

    func testReadmeBlockExtractionReadsTheBlockUnderTheHeading() throws {
        let text = "# T\n\n```swift\nbefore()\n```\n\n## Quick Start\n\nProse.\n\n"
            + "```swift\nquick()\n```\n\n```swift\nafter()\n```\n"
        XCTAssertEqual(try Self.readmeBlock(text), "quick()\n")
    }

    func testCopyMatchesTheReadmeBlock() throws {
        let readme = try String(
            contentsOf: Self.testsDirectory.appendingPathComponent("../../README.md").standardized,
            encoding: .utf8
        )
        let copy = try String(
            contentsOf: Self.testsDirectory.appendingPathComponent("ReadmeQuickStart.swift"),
            encoding: .utf8
        )
        XCTAssertEqual(
            Self.copyBody(copy),
            try Self.readmeBlock(readme),
            "Tests/SCPTests/ReadmeQuickStart.swift must match the README Quick Start block byte for byte"
        )
    }

    func testReadmeQuickStartRuns() async throws {
        try await runQuickStart()
    }
}
