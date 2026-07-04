@testable import SCP
import XCTest

// Tests for the typed trust-admission inputs (ADR-058, §7.3.2.1 / §7.3.4.4).
//
// Two layers:
//   1. Encoder wire-shape tests (`TrustAdmissionEncoderTests`) — pure Swift, no
//      linked Rust binary. They pin each encoder's output against the exact
//      `serde_json` shape the bridge deserializes (snake_case keys, bare /
//      externally-tagged enum variants, byte-arrays as number arrays, explicit
//      `null` for absent optionals).
//   2. Call-through tests (`TrustAdmissionCallThroughTests`) — invoke the
//      generated UniFFI free functions through the typed wrappers against the
//      real Rust deserializers (require the XCFramework / SCP-103). They prove
//      the serialized JSON actually parses and evaluates on the Rust side.

/// Parses two JSON strings and asserts deep structural equality
/// (order-independent — the Rust serde deserializers are key-order-agnostic).
private func assertJSONEqual(
    _ actual: String,
    _ expected: String,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    do {
        let actualObject = try JSONSerialization.jsonObject(with: Data(actual.utf8))
        let expectedObject = try JSONSerialization.jsonObject(with: Data(expected.utf8))
        XCTAssertEqual(
            actualObject as? NSObject,
            expectedObject as? NSObject,
            "actual: \(actual)",
            file: file,
            line: line
        )
    } catch {
        XCTFail("failed to parse JSON: \(error)\nactual: \(actual)", file: file, line: line)
    }
}

final class TrustAdmissionEncoderTests: XCTestCase {
    // MARK: - CapabilityRequirement encoder

    func testCapabilityRequirementEncodesSnakeCaseAndBareLevel() throws {
        let requirements = [
            CapabilityRequirement(
                capability: "scp:capability:messages-write/v1",
                verificationLevel: .challengeVerified
            ),
            CapabilityRequirement(
                capability: "scp:capability:tool-invoke/v1",
                verificationLevel: .selfAttested
            )
        ]
        let json = try encodeCapabilityRequirementsJson(requirements)
        assertJSONEqual(
            json,
            """
            [
              {"capability":"scp:capability:messages-write/v1","verification_level":"ChallengeVerified"},
              {"capability":"scp:capability:tool-invoke/v1","verification_level":"SelfAttested"}
            ]
            """
        )
    }

    // MARK: - RequireParticipation encoder

    func testRequireParticipationEncodesFactAndThreshold() throws {
        let requirements = [
            RequireParticipation(
                fact: .participationDuration,
                threshold: .atLeast(3600),
                maxAgeSecs: 86400,
                minContexts: 2
            ),
            RequireParticipation(
                fact: .governanceActionsAgainst,
                threshold: .lessThan(1),
                maxAgeSecs: 0,
                minContexts: 1
            )
        ]
        let json = try encodeRequireParticipationJson(requirements)
        assertJSONEqual(
            json,
            """
            [
              {"fact":"ParticipationDuration","threshold":{"AtLeast":3600},"max_age_secs":86400,"min_contexts":2},
              {"fact":"GovernanceActionsAgainst","threshold":{"LessThan":1},"max_age_secs":0,"min_contexts":1}
            ]
            """
        )
    }

    /// Every `ParticipationThreshold` operator maps to its externally-tagged
    /// single-key object, matching the Rust enum.
    func testAllThresholdOperatorsEncode() throws {
        let cases: [(ParticipationThreshold, [String: Int])] = [
            (.greaterThan(1), ["GreaterThan": 1]),
            (.lessThan(2), ["LessThan": 2]),
            (.atLeast(3), ["AtLeast": 3]),
            (.atMost(4), ["AtMost": 4]),
            (.equals(5), ["Equals": 5])
        ]
        for (threshold, expected) in cases {
            let req = RequireParticipation(
                fact: .toolInvocationCount,
                threshold: threshold,
                maxAgeSecs: 0,
                minContexts: 0
            )
            let json = try encodeRequireParticipationJson([req])
            let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]]
            let thresholdObj = obj?.first?["threshold"] as? [String: Int]
            XCTAssertEqual(thresholdObj, expected)
        }
    }

    // MARK: - ParticipationProfile encoder

    func testParticipationProfileEncodesThirteenFields() throws {
        let profile = ParticipationProfile(
            subjectDid: "did:key:zSubject",
            participationDurationSecs: 7200,
            governanceActionsAgainst: 0,
            governanceActionsBy: 3,
            toolInvocationCount: 9,
            toolInvocationCountAnchored: false,
            contextCreationCount: 1,
            roleProgressionCount: 2,
            attestationCount: 4,
            updatedAt: 1_700_000_000,
            eventLogRoot: Array(repeating: 1, count: 32),
            signerPublicKey: Array(repeating: 2, count: 32),
            signature: Array(repeating: 3, count: 64)
        )
        let json = try encodeParticipationProfileJson([profile])

        guard let array = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]],
              let first = array.first else {
            return XCTFail("expected a JSON array of one profile object")
        }
        XCTAssertEqual(first["subject_did"] as? String, "did:key:zSubject")
        XCTAssertEqual(first["participation_duration_secs"] as? Int, 7200)
        XCTAssertEqual(first["governance_actions_against"] as? Int, 0)
        XCTAssertEqual(first["governance_actions_by"] as? Int, 3)
        XCTAssertEqual(first["tool_invocation_count"] as? Int, 9)
        XCTAssertEqual(first["tool_invocation_count_anchored"] as? Bool, false)
        XCTAssertEqual(first["context_creation_count"] as? Int, 1)
        XCTAssertEqual(first["role_progression_count"] as? Int, 2)
        XCTAssertEqual(first["attestation_count"] as? Int, 4)
        XCTAssertEqual(first["updated_at"] as? Int, 1_700_000_000)
        XCTAssertEqual((first["event_log_root"] as? [Any])?.count, 32)
        XCTAssertEqual((first["signer_public_key"] as? [Any])?.count, 32)
        XCTAssertEqual((first["signature"] as? [Any])?.count, 64)
        // No camelCase leakage.
        XCTAssertNil(first["subjectDid"])
        XCTAssertNil(first["eventLogRoot"])
    }

    // MARK: - ChallengeVerification encoder

    func testChallengeVerificationSelfAttestedEncodesSixteenFields() throws {
        let verification = ChallengeVerification(
            verificationId: "ver-1",
            verifierDid: "did:key:zVerifier",
            subjectDid: "did:key:zSubject",
            capabilityUri: "scp:capability:schema-validation/v1",
            challengeType: "scp:capability:schema-validation/v1",
            verificationMethod: .selfAttested,
            passed: true,
            testCount: 10,
            passCount: 10,
            result: ["passed": true],
            completedAt: 1_700_000_050,
            verifiedAt: 1_700_000_100,
            expiresAt: 1_800_000_000,
            verifierSignature: Array(repeating: 7, count: 64)
        )
        let json = try encodeChallengeVerificationsJson([verification])

        guard let array = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]],
              let first = array.first else {
            return XCTFail("expected a JSON array of one verification object")
        }
        XCTAssertEqual(first["verification_id"] as? String, "ver-1")
        XCTAssertEqual(first["verifier_did"] as? String, "did:key:zVerifier")
        XCTAssertEqual(first["subject_did"] as? String, "did:key:zSubject")
        XCTAssertEqual(first["capability_uri"] as? String, "scp:capability:schema-validation/v1")
        XCTAssertEqual(first["challenge_type"] as? String, "scp:capability:schema-validation/v1")
        // Self-attested method serializes as the bare string.
        XCTAssertEqual(first["verification_method"] as? String, "SelfAttested")
        XCTAssertEqual(first["passed"] as? Bool, true)
        XCTAssertEqual(first["test_count"] as? Int, 10)
        XCTAssertEqual(first["pass_count"] as? Int, 10)
        XCTAssertNotNil(first["result"])
        XCTAssertEqual(first["completed_at"] as? Int, 1_700_000_050)
        XCTAssertEqual(first["verified_at"] as? Int, 1_700_000_100)
        XCTAssertEqual(first["expires_at"] as? Int, 1_800_000_000)
        XCTAssertEqual((first["verifier_signature"] as? [Any])?.count, 64)
        // Absent optionals serialize as explicit JSON null (present as keys).
        XCTAssertTrue(first.keys.contains("score"))
        XCTAssertTrue(first["score"] is NSNull)
        XCTAssertTrue(first.keys.contains("context_id"))
        XCTAssertTrue(first["context_id"] is NSNull)
    }

    func testChallengeVerificationChallengeVerifiedMethodIsTagged() throws {
        let verification = ChallengeVerification(
            verificationId: "ver-2",
            verifierDid: "did:key:zVerifier",
            subjectDid: "did:key:zSubject",
            capabilityUri: "scp:capability:schema-validation/v1",
            challengeType: "scp:capability:schema-validation/v1",
            verificationMethod: .challengeVerified(
                challengeType: "scp:capability:schema-validation/v1"
            ),
            passed: true,
            testCount: 5,
            passCount: 5,
            result: JSONValue.null,
            completedAt: 1,
            verifiedAt: 2,
            expiresAt: 3,
            verifierSignature: Array(repeating: 0, count: 64),
            score: 87,
            contextId: "ctx-1"
        )
        let json = try encodeChallengeVerificationsJson([verification])
        guard let array = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]],
              let first = array.first else {
            return XCTFail("expected a JSON array of one verification object")
        }
        // ChallengeVerified serializes as the externally-tagged nested object.
        let method = first["verification_method"] as? [String: Any]
        let inner = method?["ChallengeVerified"] as? [String: Any]
        XCTAssertEqual(inner?["challenge_type"] as? String, "scp:capability:schema-validation/v1")
        // Present optionals carry their values.
        XCTAssertEqual(first["score"] as? Int, 87)
        XCTAssertEqual(first["context_id"] as? String, "ctx-1")
    }

    // MARK: - Byte-length validation (encode-time, before any bridge call)

    func testWrongLengthProfileByteArraysThrowValidationBeforeBridgeCall() throws {
        let badProfile = ParticipationProfile(
            subjectDid: "did:key:zSubject",
            participationDurationSecs: 0,
            governanceActionsAgainst: 0,
            governanceActionsBy: 0,
            toolInvocationCount: 0,
            toolInvocationCountAnchored: false,
            contextCreationCount: 0,
            roleProgressionCount: 0,
            attestationCount: 0,
            updatedAt: 0,
            eventLogRoot: [1, 2, 3],
            signerPublicKey: Array(repeating: 2, count: 32),
            signature: Array(repeating: 3, count: 64)
        )
        XCTAssertThrowsError(try encodeParticipationProfileJson([badProfile])) { error in
            guard case let ScpError.Validation(msg, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(
                msg,
                "ParticipationProfile.eventLogRoot must be exactly 32 elements, got 3"
            )
            XCTAssertEqual(code, "SCP-VALID-7095")
        }
    }

    func testWrongLengthVerifierSignatureThrowsValidationBeforeBridgeCall() throws {
        let badVerification = ChallengeVerification(
            verificationId: "ver-bad",
            verifierDid: "did:key:zVerifier",
            subjectDid: "did:key:zSubject",
            capabilityUri: "scp:capability:schema-validation/v1",
            challengeType: "scp:capability:schema-validation/v1",
            verificationMethod: .selfAttested,
            passed: true,
            testCount: 1,
            passCount: 1,
            result: JSONValue.null,
            completedAt: 1,
            verifiedAt: 2,
            expiresAt: 3,
            verifierSignature: Array(repeating: 9, count: 63)
        )
        XCTAssertThrowsError(try encodeChallengeVerificationsJson([badVerification])) { error in
            guard case let ScpError.Validation(msg, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(
                msg,
                "ChallengeVerification.verifierSignature must be exactly 64 elements, got 63"
            )
            XCTAssertEqual(code, "SCP-VALID-7096")
        }
    }

    // MARK: - Agent capabilities encoder

    func testAgentCapabilitiesEncodeAsStringArray() throws {
        let json = try encodeAgentCapabilitiesJson([
            "scp:capability:messages-write/v1",
            "scp:capability:tool-invoke/v1"
        ])
        assertJSONEqual(
            json,
            #"["scp:capability:messages-write/v1","scp:capability:tool-invoke/v1"]"#
        )
    }

    // MARK: - Codable round-trips (decode is the inverse of encode)

    func testThresholdRoundTripsThroughDecode() throws {
        let original = RequireParticipation(
            fact: .roleProgressionCount,
            threshold: .greaterThan(42),
            maxAgeSecs: 10,
            minContexts: 3
        )
        let json = try encodeRequireParticipationJson([original])
        let decoded = try JSONDecoder().decode([RequireParticipation].self, from: Data(json.utf8))
        XCTAssertEqual(decoded, [original])
    }

    func testVerificationMethodRoundTripsThroughDecode() throws {
        let methods: [ChallengeVerificationMethod] = [
            .selfAttested,
            .challengeVerified(challengeType: "scp:capability:tool-integrity/v1")
        ]
        for method in methods {
            let data = try JSONEncoder().encode(method)
            let decoded = try JSONDecoder().decode(ChallengeVerificationMethod.self, from: data)
            XCTAssertEqual(decoded, method)
        }
    }
}

/// Call-through against the real Rust deserializers (SCP-103): these invoke the
/// generated UniFFI free functions through the typed wrappers, proving the
/// serialized JSON parses and evaluates on the Rust side.
final class TrustAdmissionCallThroughTests: XCTestCase {
    /// A satisfied `SelfAttested` requirement admits the agent: the capability is
    /// present in `agentCapabilities`, so the typed wrapper's serialized JSON
    /// parses and evaluates to success on the Rust side (no throw).
    func testCheckCapabilityRequirementsSelfAttestedPasses() throws {
        XCTAssertNoThrow(
            try checkCapabilityRequirements(
                contextId: "ctx-1",
                subjectDid: "did:key:zSubject",
                requirements: [
                    CapabilityRequirement(
                        capability: "scp:capability:messages-write/v1",
                        verificationLevel: .selfAttested
                    )
                ],
                agentCapabilities: ["scp:capability:messages-write/v1"],
                challengeVerifications: []
            )
        )
    }

    /// An unmet `SelfAttested` requirement (capability not declared, no matching
    /// challenge verification) is rejected by the Rust evaluator — proving the
    /// serialized JSON parsed and was evaluated, not silently dropped.
    func testCheckCapabilityRequirementsMissingCapabilityThrows() {
        XCTAssertThrowsError(
            try checkCapabilityRequirements(
                contextId: "ctx-1",
                subjectDid: "did:key:zSubject",
                requirements: [
                    CapabilityRequirement(
                        capability: "scp:capability:member-invite/v1",
                        verificationLevel: .selfAttested
                    )
                ],
                agentCapabilities: ["scp:capability:messages-write/v1"],
                challengeVerifications: []
            )
        )
    }

    /// Empty requirements are vacuously satisfied — a clean call-through proving
    /// the empty-array serialization parses on the Rust side.
    func testVerifyParticipationRequirementsEmptyPasses() throws {
        XCTAssertNoThrow(
            try verifyParticipationRequirements(
                expectedSubject: "did:key:zSubject",
                requirements: [],
                profiles: []
            )
        )
    }

    /// A real requirement paired with an unsigned (zero-signature) profile is
    /// rejected by the Rust signature check — proving the profile JSON
    /// round-tripped far enough to be signature-verified, not rejected as
    /// malformed input.
    func testVerifyParticipationRequirementsUnsignedProfileThrows() {
        let profile = ParticipationProfile(
            subjectDid: "did:key:zSubject",
            participationDurationSecs: 7200,
            governanceActionsAgainst: 0,
            governanceActionsBy: 0,
            toolInvocationCount: 0,
            toolInvocationCountAnchored: false,
            contextCreationCount: 0,
            roleProgressionCount: 0,
            attestationCount: 0,
            updatedAt: 1_700_000_000,
            eventLogRoot: Array(repeating: 0, count: 32),
            signerPublicKey: Array(repeating: 0, count: 32),
            signature: Array(repeating: 0, count: 64)
        )
        XCTAssertThrowsError(
            try verifyParticipationRequirements(
                expectedSubject: "did:key:zSubject",
                requirements: [
                    RequireParticipation(
                        fact: .participationDuration,
                        threshold: .atLeast(3600),
                        maxAgeSecs: 86400,
                        minContexts: 1
                    )
                ],
                profiles: [profile]
            )
        )
    }
}
