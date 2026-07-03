@testable import SCP
import XCTest

/// Tests for the ADR-049 Phase 2J spawn-from-Welcome joiner ops:
/// `SCP.reserveKeyPackage(identity:)` and
/// `Context.joinFromWelcome(scp:identity:creatorDid:contextId:params:reservationId:welcomeBytes:)`.
///
/// The suite links the Rust binary built with `allow_in_memory_custody`, so
/// reservation and the Welcome-processing custody/validation gates run against
/// the real engine (like `ScpClassTests` / `ToolSagaTests`). A full happy-path
/// join requires a live creator context minting a Welcome addressed to the
/// reserved `KeyPackage` — a two-party MLS handshake not reproducible in a
/// single-process unit test — so, mirroring the co-located Rust bridge tests,
/// these exercise: the reserve round-trip, single-use distinctness, the
/// local-custody gate on both ops (fails BEFORE the `KeyPackage` is consumed),
/// the DID validation gate, and the real Welcome processor rejecting a bogus
/// Welcome.
final class ContextJoinFromWelcomeTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs — the XCTest lifecycle guarantees non-nil.
    // swiftlint:disable:next implicitly_unwrapped_optional
    var scp: SCP!

    /// The canonical missing-key-material code the local-custody gate raises.
    private static let nonCustodiedCode = "SCP-IDENT-1054"

    override func setUpWithError() throws {
        try super.setUpWithError()
        scp = try SCP(storage: .inMemory)
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    // MARK: - Helpers

    /// Legible params for a joined encrypted context — the same shape
    /// `Context.create` takes.
    private func makeParams() -> ContextParams {
        ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write"],
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

    /// A syntactically valid canonical 64-hex context id (ADR-056).
    private func makeContextId() -> String {
        String(repeating: "ab", count: 32)
    }

    /// Loads `did` as a DID-only, non-custodied handle (`core_id == nil`) — the
    /// handle shape `identityLoad` returns, which the local-custody gate rejects.
    private func loadNonCustodied(_ did: String) async throws -> Identity {
        try await scp.identityLoad(did: did)
    }

    /// Asserts `body` throws `ScpError.Identity` carrying the given code.
    private func assertIdentityCode<T>(
        _ expectedCode: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> T
    ) async {
        do {
            _ = try await body()
            XCTFail("expected ScpError.Identity(\(expectedCode)) to be thrown", file: file, line: line)
        } catch let ScpError.Identity(_, code) {
            XCTAssertEqual(code, expectedCode, "unexpected identity code", file: file, line: line)
        } catch {
            XCTFail("expected ScpError.Identity, got \(error)", file: file, line: line)
        }
    }

    // MARK: - reserveKeyPackage

    /// A custodied identity reserves a single-use `KeyPackage`; both the opaque
    /// reservation id and the PUBLIC `KeyPackage` bytes come back non-empty.
    func testReserveKeyPackageRoundTrip() async throws {
        let joiner = try await scp.identityCreate(custody: "in_memory")

        let reservation = try await scp.reserveKeyPackage(identity: joiner)

        XCTAssertFalse(reservation.reservationId.isEmpty, "reservation id must be non-empty")
        XCTAssertFalse(reservation.keyPackagePublic.isEmpty, "public KeyPackage bytes must be non-empty")
    }

    /// Each reservation is single-use: two reserves under the SAME identity
    /// yield distinct reservation ids AND distinct public `KeyPackage` bytes.
    func testReserveProducesDistinctSingleUseKeyPackages() async throws {
        let joiner = try await scp.identityCreate(custody: "in_memory")

        let first = try await scp.reserveKeyPackage(identity: joiner)
        let second = try await scp.reserveKeyPackage(identity: joiner)

        XCTAssertNotEqual(
            first.reservationId,
            second.reservationId,
            "each reserve must mint a fresh single-use reservation id"
        )
        XCTAssertNotEqual(
            first.keyPackagePublic,
            second.keyPackagePublic,
            "each reserve must produce a distinct single-use KeyPackage"
        )
    }

    /// A DID-only (non-custodied) handle cannot reserve — the local-custody gate
    /// fails closed with the canonical `SCP-IDENT-1054` before any pool draw.
    func testReserveRejectsNonCustodiedIdentity() async throws {
        let created = try await scp.identityCreate(custody: "in_memory")
        let loaded = try await loadNonCustodied(created.did())

        await assertIdentityCode(Self.nonCustodiedCode) {
            try await self.scp.reserveKeyPackage(identity: loaded)
        }
    }

    // MARK: - joinFromWelcome

    /// The joiner's routing pseudonym is DERIVED from its locally-custodied
    /// identity, so a non-custodied joiner hard-fails at the derivation seam
    /// (`SCP-IDENT-1054`) BEFORE the single-use `KeyPackage` is consumed.
    func testJoinFromWelcomeRejectsNonCustodiedJoiner() async throws {
        let created = try await scp.identityCreate(custody: "in_memory")
        let loaded = try await loadNonCustodied(created.did())

        await assertIdentityCode(Self.nonCustodiedCode) {
            try await Context.joinFromWelcome(
                scp: self.scp,
                identity: loaded,
                creatorDid: "did:dht:z6MkCreatorForWelcomeJoinTest",
                contextId: self.makeContextId(),
                params: self.makeParams(),
                reservationId: "unused-reservation-id",
                welcomeBytes: Data([0x00, 0x01, 0x02])
            )
        }
    }

    /// A malformed `creatorDid` is rejected by the shared `validate_did` gate
    /// with `ScpError.Validation`, before the reservation or Welcome is touched.
    func testJoinFromWelcomeRejectsMalformedCreatorDid() async throws {
        let joiner = try await scp.identityCreate(custody: "in_memory")

        do {
            _ = try await Context.joinFromWelcome(
                scp: scp,
                identity: joiner,
                creatorDid: "not-a-did",
                contextId: makeContextId(),
                params: makeParams(),
                reservationId: "unused-reservation-id",
                welcomeBytes: Data([0x00])
            )
            XCTFail("expected a malformed creator DID to be rejected")
        } catch let ScpError.Validation(_, code) {
            XCTAssertFalse(code.isEmpty, "validation error must carry a code")
        } catch {
            XCTFail("expected ScpError.Validation, got \(error)")
        }
    }

    /// With a custodied joiner and a real reservation, a bogus (garbage) Welcome
    /// reaches the real MLS Welcome processor and is rejected with an
    /// `ScpError` — the join does not silently succeed.
    func testJoinFromWelcomeRejectsBogusWelcome() async throws {
        let joiner = try await scp.identityCreate(custody: "in_memory")
        let reservation = try await scp.reserveKeyPackage(identity: joiner)

        do {
            let ctx = try await Context.joinFromWelcome(
                scp: scp,
                identity: joiner,
                creatorDid: "did:dht:z6MkCreatorForWelcomeJoinTest",
                contextId: makeContextId(),
                params: makeParams(),
                reservationId: reservation.reservationId,
                welcomeBytes: Data(repeating: 0xEE, count: 64)
            )
            _ = ctx
            XCTFail("expected a bogus Welcome to be rejected by the MLS processor")
        } catch is ScpError {
            // Expected: the garbage Welcome fails to parse / install; the bridge
            // rolls back the reversible state and surfaces a typed ScpError.
        } catch {
            XCTFail("expected ScpError, got \(error)")
        }
    }
}
