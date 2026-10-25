@testable import SCP
import XCTest

// The TTL reset returns the bridge's typed error to its caller (spec 17
// section 17.3, "Event log write failures"). Requires the XCFramework.

final class TtlResetCallThroughTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs — the XCTest lifecycle guarantees non-nil.
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

    /// A reset with a handle another instance minted throws, where the
    /// bridge used to return nothing. The owning instance's reset is the
    /// control.
    func testResetWithAForeignHandleThrows() async throws {
        let creator = try await createInMemoryIdentity(scp)
        let handle = try await scp.contextCreate(
            identity: creator,
            params: ContextParams(
                mode: .encrypted,
                ceiling: ["messages:read"],
                ceilingPolicy: .immutable,
                governance: .singleAdmin,
                memoryScope: .ephemeral,
                ttlSeconds: 3600,
                promotable: false,
                consequenceRules: nil,
                consequenceConfig: nil
            )
        )
        try await scp.contextResetTtlTimer(handle: handle, newSeconds: 60)

        let other = try SCP(storage: .inMemory)
        do {
            try await other.contextResetTtlTimer(handle: handle, newSeconds: 60)
            XCTFail("a reset with a foreign handle must throw")
        } catch {
            XCTAssertTrue(error is ScpError, "expected the bridge's ScpError, got \(error)")
        }
        try await other.shutdown(timeoutMillis: 1000)
    }
}
