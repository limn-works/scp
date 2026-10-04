@testable import SCP
import XCTest

/// The Swift wrapper hands the caller's bearer token to the UniFFI
/// `mcpClientConnectSse`, so a Swift client passes the bearer check an SCP
/// SSE server always runs (ADR-015). The native object records the call and
/// holds no Rust pointer, so no native code runs.
final class McpClientConnectSseTests: XCTestCase {
    /// Inherits `Scp`'s `@unchecked Sendable`; only the test's one task
    /// touches `connects`.
    private final class RecordingScp: Scp {
        var connects: [(url: String, authToken: String?)] = []

        override func mcpClientConnectSse(url: String, authToken: String?) async throws -> String {
            connects.append((url: url, authToken: authToken))
            return "mcp-client-1"
        }
    }

    func testConnectSseForwardsTheBearerToken() async throws {
        let native = RecordingScp(noPointer: Scp.NoPointer())
        let scp = SCP(inner: native)

        _ = try await McpClient.connect(
            scp: scp,
            config: .sse(url: "http://127.0.0.1:9/sse", authToken: "tok-1")
        )

        XCTAssertEqual(native.connects.count, 1)
        XCTAssertEqual(native.connects.first?.url, "http://127.0.0.1:9/sse")
        XCTAssertEqual(native.connects.first?.authToken, "tok-1")
    }
}
