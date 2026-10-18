@testable import SCP
import XCTest

/// Tests that the typed ``ContextParams`` initializer forwards the ceiling the
/// caller declared, as written.
///
/// A create whose ceiling is empty fails in the bridge with `SCP-VALID-7005`
/// (construction.md M2). An initializer that replaced an empty list with a
/// default ceiling would turn that refusal into a context with capabilities
/// nobody chose, so the empty list must reach the bridge unchanged.
final class ContextParamsTypedInitTests: XCTestCase {
    private func makeParams(
        ceiling: [String],
        capabilityRequirements: [CapabilityRequirement]? = nil
    ) throws -> ContextParams {
        try ContextParams(
            mode: .encrypted,
            ceiling: ceiling,
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            consequenceRules: nil,
            consequenceConfig: nil,
            capabilityRequirements: capabilityRequirements
        )
    }

    func testEmptyCeilingStaysEmpty() throws {
        XCTAssertEqual(try makeParams(ceiling: []).ceiling, [])
    }

    func testDeclaredCeilingStandsAsWritten() throws {
        XCTAssertEqual(
            try makeParams(ceiling: ["messages:read"]).ceiling,
            ["messages:read"]
        )
    }

    func testAbsentCapabilityRequirementsStayAbsent() throws {
        XCTAssertNil(try makeParams(ceiling: ["messages:read"]).capabilityRequirementsJson)
    }

    func testCapabilityRequirementsReachTheWireField() throws {
        let params = try makeParams(
            ceiling: ["messages:read"],
            capabilityRequirements: [
                .challengeVerified(ChallengeVerifiedRequirement(
                    capability: "scp:cap:translate",
                    trustedVerifiers: ["did:dht:verifier"],
                    retryCap: RetryCap(maxRetries: 2, minCooldownSecs: 60)
                ))
            ]
        )
        let json = try XCTUnwrap(params.capabilityRequirementsJson)
        let decoded = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]]
        )
        XCTAssertEqual(decoded.count, 1)
        XCTAssertEqual(decoded[0]["capability"] as? String, "scp:cap:translate")
        XCTAssertEqual(decoded[0]["verification_level"] as? String, "ChallengeVerified")
        XCTAssertEqual(decoded[0]["trusted_verifiers"] as? [String], ["did:dht:verifier"])
        let cap = try XCTUnwrap(decoded[0]["retry_cap"] as? [String: Any])
        XCTAssertEqual(cap["max_retries"] as? Int, 2)
        XCTAssertEqual(cap["min_cooldown_secs"] as? Int, 60)
    }
}
