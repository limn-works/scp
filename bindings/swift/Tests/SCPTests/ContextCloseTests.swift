@testable import SCP
import XCTest

/// Tests that ``Context/close()`` reaches the bridge whatever the actor's
/// cached ``Context/state`` reads.
///
/// `close()` is the only path that releases the bridge's per-context UCAN
/// state, and no SDK method clears a poison, so a `close()` that refused a
/// cached ``ContextState/poisoned`` held that state for the life of the
/// process. The initializer writes ``ContextState/poisoned`` whenever
/// ``ContextHandle/state()`` throws — the getter takes `try_lock` and raises
/// `SCP-CTX-2012` under contention — or reports a string this SDK does not
/// recognize, so the cached value reaches `.poisoned` without the crash
/// watchdog poisoning anything. The bridge reads the supervisor actor and
/// decides the close: it releases for an absent, poisoned, or terminal
/// supervisor state, and it throws for the live non-terminal states
/// `creating`, `closing`, and `migrating_out`. A `closing` context sits in
/// the §5.9 cooperative window, and the supervisor dispatch a release would
/// skip carries the only `context:close` capability check the close path has.
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
    /// dispatches the close and releases its per-context state. Before this
    /// test existed, `close()` compared the cached state against `.active`,
    /// returned without calling the bridge, and left the state resident with
    /// no error for the caller to see.
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
    /// The first close set the `didClose` flag, which is what `close()` now
    /// reads instead of the cached state, so the idempotence the old
    /// `state == .active` comparison provided survives.
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
