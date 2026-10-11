@testable import SCP
import XCTest

/// Tests that ``Context/close()`` reaches the bridge whatever the actor's
/// cached ``Context/state`` reads, and returns without a second bridge call
/// once it has closed.
final class ContextCloseTests: XCTestCase {
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

    /// Params for a `SingleAdmin` context the creator can close.
    private func makeParams() -> ContextParams {
        ContextParams(
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
    }

    /// A context whose cached state reads `.poisoned` still closes.
    ///
    /// The supervisor actor this handle names is `Active`, so the bridge
    /// dispatches the close and `close()` records `.closed`.
    func testCloseFromAPoisonedCachedStateReachesTheBridge() async throws {
        let creator = try await scp.identityCreate(custody: "in_memory")
        let context = try await Context.create(
            scp: scp,
            identity: creator,
            params: makeParams(),
            initialState: .poisoned
        )

        try await context.close()

        let stateAfterClose = await context.state
        XCTAssertEqual(
            stateAfterClose,
            .closed,
            "close() must reach the bridge and record the close"
        )
    }

    /// A second `close()` returns without calling the bridge again.
    ///
    /// The supervisor actor reports `closing` after the first close, and the
    /// bridge refuses a close in that state, so a second bridge call would
    /// throw.
    func testSecondCloseStaysIdempotent() async throws {
        let creator = try await scp.identityCreate(custody: "in_memory")
        let context = try await Context.create(
            scp: scp,
            identity: creator,
            params: makeParams()
        )

        try await context.close()
        try await context.close()

        let stateAfterClose = await context.state
        XCTAssertEqual(stateAfterClose, .closed)
    }
}
