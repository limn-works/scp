@testable import SCP
import XCTest

/// Tests for the SDK-level `SCP.mcpDisableStdioAllowlist` ceremony.
///
/// The Swift wrapper requires `iTrustAllCommands: true` before delegating
/// to the inner UniFFI-generated `Scp` and emits a runtime warning when
/// proceeding. The throw happens at the wrapper layer before any native
/// call — but constructing `SCP()` itself requires the UniFFI library, so
/// the suite skips gracefully when the binary is unavailable.
final class McpAllowlistTests: XCTestCase {
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

    /// `mcpDisableStdioAllowlist()` (no arg) must throw a Validation error
    /// referencing the ceremony — the native disable must NOT be invoked.
    func testDisableThrowsWhenCeremonyOmitted() {
        XCTAssertThrowsError(try scp.mcpDisableStdioAllowlist()) { error in
            guard let scpError = error as? ScpError else {
                XCTFail("expected ScpError, got \(error)")
                return
            }
            switch scpError {
            case let .Validation(message, code):
                XCTAssertTrue(
                    message.contains("iTrustAllCommands"),
                    "expected ceremony message, got: \(message)"
                )
                XCTAssertEqual(code, "SCP-MCP-10010")
            default:
                XCTFail("expected ScpError.Validation, got \(scpError)")
            }
        }
    }

    /// `mcpDisableStdioAllowlist(iTrustAllCommands: false)` must throw —
    /// explicitly opting out is the same as not opting in.
    func testDisableThrowsWhenCeremonyExplicitlyFalse() {
        XCTAssertThrowsError(try scp.mcpDisableStdioAllowlist(iTrustAllCommands: false))
    }

    /// `mcpDisableStdioAllowlist(iTrustAllCommands: true)` must succeed
    /// and the snapshot must report `unrestricted = true`. Other instances
    /// must be unaffected.
    func testDisableSucceedsWhenCeremonyOptedIn() async throws {
        try scp.mcpDisableStdioAllowlist(iTrustAllCommands: true)

        let aState = try scp.mcpGetStdioAllowlist()
        XCTAssertTrue(aState.unrestricted, "instance a should be unrestricted")

        // Sibling instance must remain restricted (per-instance isolation).
        let other = try SCP(storage: .inMemory)
        let bState = try other.mcpGetStdioAllowlist()
        XCTAssertFalse(bState.unrestricted, "instance b must remain restricted")
        try await other.shutdown(timeoutMillis: 1000)
    }
}
