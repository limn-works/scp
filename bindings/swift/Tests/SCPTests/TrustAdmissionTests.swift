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

final class ChallengeVerifiedRequirementTests: XCTestCase {
    /// A `ChallengeVerified` requirement with no trusted verifier cannot be
    /// built: the initializer throws the bridge's code for the same defect.
    func testChallengeVerifiedWithoutVerifiersFailsToConstructWith7150() {
        XCTAssertThrowsError(
            try ChallengeVerifiedRequirement(capability: "scp:capability:messages-write/v1", trustedVerifiers: [])
        ) { error in
            guard case let ScpError.Validation(_, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(code, "SCP-VALID-7150")
            XCTAssertEqual(code, invalidRequirementCode)
        }
    }
}

final class TrustAdmissionEncoderTests: XCTestCase {
    // MARK: - CapabilityRequirement encoder

    func testCapabilityRequirementEncodesSnakeCaseAndBareLevel() throws {
        let requirements: [CapabilityRequirement] = try [
            .challengeVerified(ChallengeVerifiedRequirement(
                capability: "scp:capability:messages-write/v1",
                trustedVerifiers: ["did:dht:verifier"],
                retryCap: RetryCap(maxRetries: 2, minCooldownSecs: 60)
            )),
            .selfAttested(capability: "scp:capability:outlet-invoke/v1")
        ]
        let json = try encodeCapabilityRequirementsJson(requirements)
        assertJSONEqual(
            json,
            """
            [
              {"capability":"scp:capability:messages-write/v1","verification_level":"ChallengeVerified",
               "trusted_verifiers":["did:dht:verifier"],
               "retry_cap":{"max_retries":2,"min_cooldown_secs":60}},
              {"capability":"scp:capability:outlet-invoke/v1","verification_level":"SelfAttested",
               "trusted_verifiers":[],"retry_cap":null}
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
                fact: .outletInvocationCount,
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
            outletInvocationCount: 9,
            outletInvocationCountAnchored: false,
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
        XCTAssertEqual(first["outlet_invocation_count"] as? Int, 9)
        XCTAssertEqual(first["outlet_invocation_count_anchored"] as? Bool, false)
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

    private func makeVerification(
        verifierSignature: [UInt8] = Array(repeating: 7, count: 64),
        suiteDigest: String = String(repeating: "cd", count: 32),
        score: UInt32 = 10000
    ) -> ChallengeVerification {
        ChallengeVerification(
            verificationId: String(repeating: "ab", count: 32),
            verifier: "did:key:zVerifier",
            subject: "did:key:zSubject",
            capabilityUri: "scp:capability:schema-validation/v1",
            definitionDigest: String(repeating: "ef", count: 32),
            suiteDigest: suiteDigest,
            challengeId: String(repeating: "01", count: 32),
            attempt: 1,
            responseDigest: String(repeating: "02", count: 32),
            maxRetries: 2,
            cooldownSecs: 60,
            passThresholdBps: 8000,
            minCategoryCases: 1,
            passed: true,
            score: score,
            testCount: 20,
            passCount: 20,
            challengeCreatedAt: 1_700_000_000,
            challengeExpiresAt: 1_700_003_600,
            timestamp: 1_700_000_100,
            expiresAt: 1_700_086_500,
            contextId: "ctx-1",
            verifierSignature: verifierSignature
        )
    }

    func testChallengeVerificationEncodesTwentyThreeSnakeCaseFields() throws {
        let json = try encodeChallengeVerificationsJson([makeVerification()])
        assertJSONEqual(
            json,
            """
            [{
              "verification_id": "\(String(repeating: "ab", count: 32))",
              "verifier": "did:key:zVerifier",
              "subject": "did:key:zSubject",
              "capability_uri": "scp:capability:schema-validation/v1",
              "definition_digest": "\(String(repeating: "ef", count: 32))",
              "suite_digest": "\(String(repeating: "cd", count: 32))",
              "challenge_id": "\(String(repeating: "01", count: 32))",
              "attempt": 1,
              "response_digest": "\(String(repeating: "02", count: 32))",
              "max_retries": 2,
              "cooldown_secs": 60,
              "pass_threshold_bps": 8000,
              "min_category_cases": 1,
              "passed": true,
              "score": 10000,
              "test_count": 20,
              "pass_count": 20,
              "challenge_created_at": 1700000000,
              "challenge_expires_at": 1700003600,
              "timestamp": 1700000100,
              "expires_at": 1700086500,
              "context_id": "ctx-1",
              "verifier_signature": \(Array(repeating: 7, count: 64))
            }]
            """
        )
    }

    func testChallengeVerificationDecodesTheBridgeRecord() throws {
        let verification = makeVerification()
        let encoded = try encodeChallengeVerificationsJson([verification])
        let record = String(encoded.dropFirst().dropLast())
        XCTAssertEqual(try decodeChallengeVerificationJson(record), verification)
    }

    func testChallengeVerificationDecodeRefusesMalformedRecords() throws {
        let encoded = try encodeChallengeVerificationsJson([makeVerification()])
        let record = String(encoded.dropFirst().dropLast())
        for (bad, message) in [
            (
                record.replacingOccurrences(of: "\"score\":10000", with: "\"score\":10001"),
                "ChallengeVerification.score must be in [0, 10000], got 10001"
            ),
            (
                record.replacingOccurrences(
                    of: String(repeating: "ab", count: 32), with: String(repeating: "AB", count: 32)
                ),
                "ChallengeVerification.verificationId must be 64 lowercase hex characters"
            ),
            (
                record.replacingOccurrences(
                    of: String(repeating: "ef", count: 32), with: "ef"
                ),
                "ChallengeVerification.definitionDigest must be 64 lowercase hex characters"
            ),
            (
                record.replacingOccurrences(
                    of: String(repeating: "02", count: 32), with: String(repeating: "0g", count: 32)
                ),
                "ChallengeVerification.responseDigest must be 64 lowercase hex characters"
            )
        ] {
            XCTAssertNotEqual(bad, record)
            XCTAssertThrowsError(try decodeChallengeVerificationJson(bad)) { error in
                guard case let ScpError.Validation(msg, code) = error else {
                    return XCTFail("expected ScpError.Validation, got \(error)")
                }
                XCTAssertEqual(msg, message)
                XCTAssertEqual(code, "SCP-VALID-7096")
            }
        }
        // A record missing a signed field is not a record.
        let missing = record.replacingOccurrences(of: "\"min_category_cases\":1,", with: "")
        XCTAssertNotEqual(missing, record)
        XCTAssertThrowsError(try decodeChallengeVerificationJson(missing)) { error in
            guard case let ScpError.Validation(_, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(code, "SCP-VALID-7096")
        }
    }

    // MARK: - Byte-length validation (encode-time, before any bridge call)

    func testWrongLengthProfileByteArraysThrowValidationBeforeBridgeCall() throws {
        let badProfile = ParticipationProfile(
            subjectDid: "did:key:zSubject",
            participationDurationSecs: 0,
            governanceActionsAgainst: 0,
            governanceActionsBy: 0,
            outletInvocationCount: 0,
            outletInvocationCountAnchored: false,
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
        let badVerification = makeVerification(verifierSignature: Array(repeating: 9, count: 63))
        XCTAssertThrowsError(
            try encodeChallengeVerificationsJson([makeVerification(suiteDigest: "cd")])
        ) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(msg, "ChallengeVerification.suiteDigest must be 64 lowercase hex characters")
        }
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
            "scp:capability:outlet-invoke/v1"
        ])
        assertJSONEqual(
            json,
            #"["scp:capability:messages-write/v1","scp:capability:outlet-invoke/v1"]"#
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
}

/// Call-through against the real Rust deserializers (SCP-103): these invoke the
/// generated UniFFI bindings through the typed wrappers, proving the
/// serialized JSON parses and evaluates on the Rust side.
final class TrustAdmissionCallThroughTests: XCTestCase {
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

    private let messagesWrite: [CapabilityRequirement] = [
        .selfAttested(capability: "scp:capability:messages-write/v1")
    ]

    /// A satisfied `SelfAttested` requirement admits the agent: the context's
    /// governance holds the requirement and the capability is present in
    /// `agentCapabilities`, so the check succeeds on the Rust side (no throw).
    func testCheckCapabilityRequirementsSelfAttestedPasses() async throws {
        let contextId = try await contextRequiring(scp, messagesWrite)
        let subject = try await createInMemoryIdentity(scp)
        try await scp.checkCapabilityRequirements(
            contextId: contextId,
            subjectDid: subject.did(),
            agentCapabilities: ["scp:capability:messages-write/v1"],
            challengeVerifications: []
        )
    }

    /// An unmet `SelfAttested` requirement is rejected by the Rust evaluator,
    /// proving the context's stored requirements were read, not dropped.
    func testCheckCapabilityRequirementsMissingCapabilityThrows() async throws {
        let contextId = try await contextRequiring(scp, messagesWrite)
        let subject = try await createInMemoryIdentity(scp)
        await assertValidationCode("SCP-VALID-7076") {
            try await self.scp.checkCapabilityRequirements(
                contextId: contextId,
                subjectDid: subject.did(),
                agentCapabilities: ["scp:capability:member-invite/v1"],
                challengeVerifications: []
            )
        }
    }

    /// A subject DID that is not canonical is refused before evaluation.
    func testCheckCapabilityRequirementsNonCanonicalSubjectThrows() async throws {
        let contextId = try await contextRequiring(scp, messagesWrite)
        await assertValidationCode(nonCanonicalIdentifierCode) {
            try await self.scp.checkCapabilityRequirements(
                contextId: contextId,
                subjectDid: "did:dht:zSubject",
                agentCapabilities: ["scp:capability:messages-write/v1"],
                challengeVerifications: []
            )
        }
    }

    /// A `ChallengeVerified` requirement backed only by an unsigned
    /// (zero-signature) record is unmet: the 23-field record deserialized on
    /// the Rust side and its signature failed, so it counts for nothing.
    func testCheckCapabilityRequirementsUnsignedRecordThrows() async throws {
        let verifier = try await createInMemoryIdentity(scp)
        let subject = try await createInMemoryIdentity(scp)
        let capability = "scp:capability:schema-validation/v1"
        let contextId = try await contextRequiring(scp, [
            .challengeVerified(ChallengeVerifiedRequirement(capability: capability, trustedVerifiers: [verifier.did()]))
        ])
        let now = UInt64(Date().timeIntervalSince1970)
        let record = ChallengeVerification(
            verificationId: String(repeating: "ab", count: 32),
            verifier: verifier.did(),
            subject: subject.did(),
            capabilityUri: capability,
            definitionDigest: String(repeating: "ef", count: 32),
            suiteDigest: String(repeating: "cd", count: 32),
            challengeId: String(repeating: "01", count: 32),
            attempt: 1,
            responseDigest: String(repeating: "02", count: 32),
            maxRetries: 0,
            cooldownSecs: 0,
            passThresholdBps: 8000,
            minCategoryCases: 1,
            passed: true,
            score: 10000,
            testCount: 20,
            passCount: 20,
            challengeCreatedAt: now,
            challengeExpiresAt: now + 3600,
            timestamp: now,
            expiresAt: now + 86400,
            contextId: contextId,
            verifierSignature: Array(repeating: 0, count: 64)
        )
        await assertValidationCode("SCP-VALID-7076") {
            try await self.scp.checkCapabilityRequirements(
                contextId: contextId,
                subjectDid: subject.did(),
                agentCapabilities: [],
                challengeVerifications: [record]
            )
        }
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
            outletInvocationCount: 0,
            outletInvocationCountAnchored: false,
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

/// A context on `scp` whose governance holds `requirements`; returns its id.
func contextRequiring(_ scp: SCP, _ requirements: [CapabilityRequirement]) async throws -> String {
    let creator = try await createInMemoryIdentity(scp)
    return try await scp.contextCreate(
        identity: creator,
        params: ContextParams(
            mode: .encrypted,
            ceiling: ["messages:read", "messages:write"],
            ceilingPolicy: .immutable,
            governance: .singleAdmin,
            memoryScope: .ephemeral,
            ttlSeconds: 3600,
            promotable: false,
            consequenceRules: nil,
            consequenceConfig: nil,
            capabilityRequirements: requirements
        )
    ).contextId()
}

/// Asserts `body` throws ``ScpError/Validation(msg:code:)`` with `code`.
func assertValidationCode(
    _ code: String,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () async throws -> Void
) async {
    do {
        try await body()
        XCTFail("expected ScpError.Validation \(code)", file: file, line: line)
    } catch let ScpError.Validation(_, actual) {
        XCTAssertEqual(actual, code, file: file, line: line)
    } catch {
        XCTFail("expected ScpError.Validation, got \(error)", file: file, line: line)
    }
}
