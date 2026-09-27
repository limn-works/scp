import Foundation
import SCP
import XCTest

/// Runs the quick start from `bindings/swift/README.md` verbatim, so a reader
/// who copies that block runs code this suite proved.
///
/// The block between the two marker comments is the README's, unchanged. What
/// surrounds it is the harness a README reader gets from process exit instead:
/// the DID assertion and the shutdown. A change to either copy that the other
/// does not mirror fails review, so the README stops drifting from what runs.
///
/// Requires an XCFramework built with the `testing` feature
/// (`bindings/swift/build-xcframework.sh --dev`): `"in_memory"` custody and the
/// pre-rotation commitment both need it, and the README says so.
final class ReadmeQuickStartTests: XCTestCase {
    func testReadmeQuickStartRunsEndToEnd() async throws {
        // ── README block starts here ──────────────────────────────────────
        let scp = try SCP(storage: .inMemory)

        let identity = try await scp.identityCreate(custody: "in_memory")
        print("DID: \(identity.did())")

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

        try await scp.contextSend(
            handle: ctx,
            identity: identity,
            payload: Data("Hello from SCP".utf8),
            spendingUcanJwt: nil
        )

        try await scp.contextClose(handle: ctx, identity: identity)
        // ── README block ends here ────────────────────────────────────────

        XCTAssertTrue(
            identity.did().hasPrefix("did:"),
            "the quick start must mint a DID"
        )
        try await scp.shutdown(timeout: 1)
    }
}
