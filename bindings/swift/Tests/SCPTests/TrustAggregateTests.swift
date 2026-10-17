@testable import SCP
import XCTest

// Tests for the typed trust-aggregation inputs (ADR-058, §7.3).
//
// Encoder wire-shape tests — pure Swift, no linked Rust binary. They pin each
// encoder's output against the exact `serde_json` shape the bridge
// deserializes (snake_case keys, bare AttestationType map keys, byte arrays
// as number arrays, explicit `null` for an absent attestor attestation, and
// the Rust serde defaults for the ThresholdRequirement penalty fields).

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

/// A structurally-valid `EventLogEntry` with real 32/64 byte arrays.
private func makeEventLogEntry(
    prevHash: [UInt8] = Array(repeating: 0, count: 32),
    signature: [UInt8] = Array(repeating: 5, count: 64),
    payloadData: [UInt8] = []
) -> EventLogEntry {
    EventLogEntry(
        eventType: "MessageSent",
        actorDid: "did:dht:actor",
        timestamp: 1_700_000_000,
        sequence: 0,
        payload: EventLogEntryPayload(data: payloadData),
        prevHash: prevHash,
        signature: signature
    )
}

final class TrustAggregateEncoderTests: XCTestCase {
    // MARK: - EventLogEntry encoder

    func testEventLogEntryEncodesSevenSnakeCaseFields() throws {
        let json = try encodeEventLogEntriesJson([
            makeEventLogEntry(
                prevHash: Array(0 ..< 32),
                payloadData: [1, 2, 3]
            )
        ])
        assertJSONEqual(
            json,
            """
            [
              {
                "event_type": "MessageSent",
                "actor_did": "did:dht:actor",
                "timestamp": 1700000000,
                "sequence": 0,
                "payload": {"data": [1, 2, 3]},
                "prev_hash": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
                "signature": \(Array(repeating: 5, count: 64))
              }
            ]
            """
        )
    }

    func testWrongLengthEventByteArraysThrowValidationBeforeBridgeCall() throws {
        XCTAssertThrowsError(
            try encodeEventLogEntriesJson([makeEventLogEntry(prevHash: [1, 2, 3])])
        ) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(msg, "EventLogEntry.prevHash must be exactly 32 elements, got 3")
        }
        XCTAssertThrowsError(
            try encodeEventLogEntriesJson([
                makeEventLogEntry(signature: Array(repeating: 5, count: 63))
            ])
        ) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(msg, "EventLogEntry.signature must be exactly 64 elements, got 63")
        }
    }

    // MARK: - Merkle root encoder

    func testMerkleRootEncodesAsNumberArray() throws {
        let json = try encodeMerkleRootJson(Array(0 ..< 32))
        assertJSONEqual(json, "\(Array(0 ..< 32))")
    }

    func testWrongLengthMerkleRootThrowsValidationBeforeBridgeCall() throws {
        XCTAssertThrowsError(try encodeMerkleRootJson([1, 2, 3])) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(
                msg,
                "AggregatedTrustInput.merkleRoot must be exactly 32 elements, got 3"
            )
        }
    }

    // MARK: - ThresholdRequirement encoder

    func testThresholdRequirementsEncodeWithBareTypeKeysAndSerdeDefaults() throws {
        let json = try encodeThresholdRequirementsJson([
            .endorsement: ThresholdRequirement(
                requiredCount: 2,
                totalAttestors: 3,
                independenceThreshold: 0.5
            )
        ])
        assertJSONEqual(
            json,
            """
            {
              "Endorsement": {
                "required_count": 2,
                "total_attestors": 3,
                "independence_threshold": 0.5,
                "shared_context_penalty": 0.1,
                "shared_context_penalty_cap": 0.5,
                "mutual_endorsement_penalty": 0.2
              }
            }
            """
        )
    }

    func testAllAttestationTypesEncodeAsBareVariantStrings() {
        let expected = [
            "IdentityLink", "CapabilityDelegation", "OutletIntegrity", "AgentCapability",
            "Endorsement", "RoleAssignment", "ContextEndorsement", "ParticipationWitness"
        ]
        XCTAssertEqual(AttestationType.allCases.map(\.rawValue).sorted(), expected.sorted())
    }

    // MARK: - AttestorInfo encoder

    func testAttestorInfoEncodesExplicitNullAbsentAttestation() throws {
        let json = try encodeAttestorSetsJson([
            .endorsement: [
                AttestorInfo(
                    did: "did:dht:attestor",
                    contextMemberships: ["ctx-1", "ctx-2"],
                    endorsements: ["did:dht:other"]
                )
            ]
        ])
        assertJSONEqual(
            json,
            """
            {
              "Endorsement": [
                {
                  "did": "did:dht:attestor",
                  "context_memberships": ["ctx-1", "ctx-2"],
                  "endorsements": ["did:dht:other"],
                  "attestation": null
                }
              ]
            }
            """
        )
    }

    func testAttestorInfoEncodesNestedEnvelopeInSerdeShape() throws {
        let json = try encodeAttestorSetsJson([
            .endorsement: [
                AttestorInfo(
                    did: "did:dht:attestor",
                    contextMemberships: [],
                    endorsements: [],
                    attestation: CachedAttestationEnvelope(
                        id: "att-1",
                        attestationType: "Endorsement",
                        issuer: "did:dht:attestor",
                        subject: "did:dht:subject",
                        claim: ["endorsed": true],
                        issuedAt: 1000,
                        revocationStatus: .string("Active"),
                        signature: [1, 2, 3]
                    )
                )
            ]
        ])
        assertJSONEqual(
            json,
            """
            {
              "Endorsement": [
                {
                  "did": "did:dht:attestor",
                  "context_memberships": [],
                  "endorsements": [],
                  "attestation": {
                    "id": "att-1",
                    "attestation_type": "Endorsement",
                    "issuer": "did:dht:attestor",
                    "subject": "did:dht:subject",
                    "claim": {"endorsed": true},
                    "issued_at": 1000,
                    "revocation_status": "Active",
                    "signature": [1, 2, 3]
                  }
                }
              ]
            }
            """
        )
    }
}

// MARK: - Challenge trust-input encoders (§7.3.4, ADR-058)

/// A structurally-valid attestation envelope for the verify path.
private func makeAttestationEnvelope(issuer: String = "did:dht:zIssuer") -> CachedAttestationEnvelope {
    CachedAttestationEnvelope(
        id: "att-1",
        attestationType: "AgentCapability",
        issuer: issuer,
        subject: "did:dht:zSubject",
        claim: ["capability": "scp:capability:schema-validation/v1"],
        issuedAt: 1_700_000_000,
        revocationStatus: .string("Active"),
        signature: Array(repeating: 3, count: 64)
    )
}

private let schemaUri = "scp:capability:schema-validation/v1"

/// `count` exact-match cases whose weights sum to 10000.
private func makeTestCases(_ count: Int) -> [TestCase] {
    let weight = UInt32(10000 / count)
    return (0 ..< count).map { index in
        TestCase(
            testId: "t\(index)",
            input: ["i": .integer(Int64(index))],
            expected: .exactMatch(value: ["ok": true]),
            category: "basic",
            weight: index == 0 ? 10000 - weight * UInt32(count - 1) : weight
        )
    }
}

/// A structurally-valid `ChallengeRequest` with a real 64-byte signature.
private func makeChallengeRequest(
    signature: [UInt8] = Array(repeating: 8, count: 64),
    challengeId: String = String(repeating: "ab", count: 32),
    answerCommitment: String = String(repeating: "cc", count: 32)
) -> ChallengeRequest {
    ChallengeRequest(
        challengeId: challengeId,
        capabilityUri: schemaUri,
        definitionDigest: String(repeating: "dd", count: 32),
        testCases: [
            ChallengeCase(
                testId: "t0", input: ["i": 0], category: "basic", weight: 10000,
                answerCommitment: answerCommitment
            )
        ],
        createdAt: 1_700_000_000,
        expiresAt: 1_700_003_600,
        maxRetries: 2,
        cooldownSecs: 60,
        passThresholdBps: 8000,
        contextId: "ctx-1",
        verifier: "did:dht:zVerifier",
        subject: "did:dht:zSubject",
        verifierSignature: signature
    )
}

/// A structurally-valid `ChallengeResponse` with a real 64-byte signature.
private func makeChallengeResponse(
    signature: [UInt8] = Array(repeating: 4, count: 64),
    requestDigest: String = String(repeating: "ee", count: 32)
) -> ChallengeResponse {
    ChallengeResponse(
        challengeId: String(repeating: "ab", count: 32),
        requestDigest: requestDigest,
        subject: "did:dht:zSubject",
        attempt: 1,
        outputs: [TestOutput(testId: "t0", output: ["ok": true])],
        subjectSignature: signature
    )
}

/// Asserts `body` throws ``ScpError/Validation(msg:code:)`` with `message`
/// and `SCP-VALID-7098`.
private func assertChallengeInputError(
    _ message: String,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ body: () throws -> Void
) {
    XCTAssertThrowsError(try body(), file: file, line: line) { error in
        guard case let ScpError.Validation(msg, code) = error else {
            return XCTFail("expected ScpError.Validation, got \(error)", file: file, line: line)
        }
        XCTAssertEqual(msg, message, file: file, line: line)
        XCTAssertEqual(code, "SCP-VALID-7098", file: file, line: line)
    }
}

final class ChallengeTrustInputEncoderTests: XCTestCase {
    func testAttestationEnvelopeEncodesSingleSerdeShape() throws {
        let json = try encodeAttestationJson(makeAttestationEnvelope())
        assertJSONEqual(
            json,
            """
            {
              "id": "att-1",
              "attestation_type": "AgentCapability",
              "issuer": "did:dht:zIssuer",
              "subject": "did:dht:zSubject",
              "claim": {"capability": "scp:capability:schema-validation/v1"},
              "issued_at": 1700000000,
              "revocation_status": "Active",
              "signature": \(Array(repeating: 3, count: 64))
            }
            """
        )
    }

    func testChallengeRequestEncodesThirteenSnakeCaseFieldsAndDecodesBack() throws {
        let request = makeChallengeRequest()
        let json = try encodeChallengeRequestJson(request)
        assertJSONEqual(
            json,
            """
            {
              "challenge_id": "\(String(repeating: "ab", count: 32))",
              "capability_uri": "scp:capability:schema-validation/v1",
              "definition_digest": "\(String(repeating: "dd", count: 32))",
              "test_cases": [{"test_id": "t0", "input": {"i": 0}, "category": "basic", "weight": 10000,
                "answer_commitment": "\(String(repeating: "cc", count: 32))"}],
              "created_at": 1700000000,
              "expires_at": 1700003600,
              "max_retries": 2,
              "cooldown_secs": 60,
              "pass_threshold_bps": 8000,
              "context_id": "ctx-1",
              "verifier": "did:dht:zVerifier",
              "subject": "did:dht:zSubject",
              "verifier_signature": \(Array(repeating: 8, count: 64))
            }
            """
        )
        XCTAssertEqual(try decodeChallengeRequestJson(json), request)
    }

    func testChallengeRequestDecodeRefusesAMissingField() throws {
        let json = try encodeChallengeRequestJson(makeChallengeRequest())
            .replacingOccurrences(of: "\"pass_threshold_bps\":8000,", with: "")
        XCTAssertFalse(json.contains("pass_threshold_bps"))
        XCTAssertThrowsError(try decodeChallengeRequestJson(json)) { error in
            guard case let ScpError.Validation(_, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(code, "SCP-VALID-7098")
        }
    }

    func testEveryExpectedOutputVariantEncodesTagged() throws {
        let variants: [(ExpectedOutput, String)] = [
            (.exactMatch(value: [1, "a"]), #"{"ExactMatch":{"value":[1,"a"]}}"#),
            (.schemaMatch(schema: ["type": "object"]), #"{"SchemaMatch":{"schema":{"type":"object"}}}"#),
            (.containsAll(required: ["a", "b"]), #"{"ContainsAll":{"required":["a","b"]}}"#),
            (.containsNone(forbidden: ["x"]), #"{"ContainsNone":{"forbidden":["x"]}}"#),
            (.customEval(evaluatorOutletId: "o-1"), #"{"CustomEval":{"evaluator_outlet_id":"o-1"}}"#)
        ]
        for (expected, wire) in variants {
            let testCase = TestCase(testId: "t0", input: ["i": 0], expected: expected, category: "basic", weight: 10000)
            let casesJson = try encodeTestCasesJson([testCase])
            let cases = try XCTUnwrap(
                JSONSerialization.jsonObject(with: Data(casesJson.utf8)) as? [[String: Any]]
            )
            let encodedExpected = try JSONSerialization.data(
                withJSONObject: XCTUnwrap(cases.first?["expected"]), options: [.sortedKeys]
            )
            let wireExpected = try JSONSerialization.data(
                withJSONObject: JSONSerialization.jsonObject(with: Data(wire.utf8)), options: [.sortedKeys]
            )
            XCTAssertEqual(encodedExpected, wireExpected)
        }
    }

    func testChallengeResponseEncodesSixSnakeCaseFieldsAndDecodesBack() throws {
        let response = makeChallengeResponse()
        let json = try encodeChallengeResponseJson(response)
        assertJSONEqual(
            json,
            """
            {
              "challenge_id": "\(String(repeating: "ab", count: 32))",
              "request_digest": "\(String(repeating: "ee", count: 32))",
              "subject": "did:dht:zSubject",
              "attempt": 1,
              "outputs": [{"test_id": "t0", "output": {"ok": true}}],
              "subject_signature": \(Array(repeating: 4, count: 64))
            }
            """
        )
        XCTAssertEqual(try decodeChallengeResponseJson(json), response)
        try assertJSONEqual(
            encodeTestOutputsJson(response.outputs),
            #"[{"test_id": "t0", "output": {"ok": true}}]"#
        )
    }

    func testCaseResultsDecodeWithAndWithoutReason() throws {
        XCTAssertEqual(
            try decodeCaseResultsJson(#"[{"passed":true,"reason":null},{"passed":false,"reason":"mismatch"}]"#),
            [CaseResult(passed: true, reason: nil), CaseResult(passed: false, reason: "mismatch")]
        )
        XCTAssertThrowsError(try decodeCaseResultsJson(#"{"passed":true}"#)) { error in
            guard case let ScpError.Validation(_, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(code, "SCP-VALID-7098")
        }
    }

    func testMalformedChallengeInputsThrowBeforeBridgeCall() {
        assertChallengeInputError("ChallengeRequest.verifierSignature must be exactly 64 elements, got 3") {
            _ = try encodeChallengeRequestJson(makeChallengeRequest(signature: [1, 2, 3]))
        }
        assertChallengeInputError("ChallengeRequest.challengeId must be 64 lowercase hex characters") {
            _ = try encodeChallengeRequestJson(makeChallengeRequest(challengeId: "chal-1"))
        }
        assertChallengeInputError("ChallengeCase.answerCommitment must be 64 lowercase hex characters") {
            _ = try encodeChallengeRequestJson(
                makeChallengeRequest(answerCommitment: String(repeating: "CC", count: 32))
            )
        }
        assertChallengeInputError("ChallengeResponse.subjectSignature must be exactly 64 elements, got 63") {
            _ = try encodeChallengeResponseJson(
                makeChallengeResponse(signature: Array(repeating: 4, count: 63))
            )
        }
        assertChallengeInputError("ChallengeResponse.requestDigest must be 64 lowercase hex characters") {
            _ = try encodeChallengeResponseJson(makeChallengeResponse(requestDigest: "ee"))
        }
    }
}

/// Call-through against the real Rust bridge: these invoke the challenge
/// operations through the typed wrappers.
final class ChallengeTrustInputCallThroughTests: XCTestCase {
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

    /// A context on `scp` whose governance requires `schemaUri` graded by
    /// `verifierDid`.
    private func requiringContext(verifierDid: String) async throws -> String {
        try await contextRequiring(scp, [
            CapabilityRequirement(
                capability: schemaUri,
                verificationLevel: .challengeVerified,
                trustedVerifiers: [verifierDid]
            )
        ])
    }

    /// A 3600-second challenge from `verifier` to `subject` for `schemaUri`,
    /// returned once its creation second has passed. Grading is strictly
    /// inside the window (spec 07 §7.3.4), so a grade in that second is
    /// refused; this waits it out on the wall clock the bridge reads.
    private func gradableChallenge(
        _ verifier: Identity, _ subject: String, _ cases: [TestCase], _ contextId: String
    ) async throws -> ChallengeRequest {
        let request = try await scp.trustCreateChallenge(
            verifier: verifier, subject: subject, capabilityUri: schemaUri,
            testCases: cases, contextId: contextId, windowSecs: 3600
        )
        while Date().timeIntervalSince1970 < Double(request.createdAt + 1) {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        return request
    }

    /// An output that passes every case `makeTestCases` writes.
    private func passingOutputs(_ cases: [TestCase]) -> [TestOutput] {
        cases.map { TestOutput(testId: $0.testId, output: ["ok": true]) }
    }

    func testTrustVerifyAttestationWithoutAResolverFailsClosedWith7052() async throws {
        // An instance with no identity has no DID resolver, so the issuer's
        // `#active` key cannot be resolved: a coded SCP-VALID-7052 error,
        // never a verdict. The issuer DID in the message proves the envelope
        // parsed on the real Rust deserializer (a parse failure is 7012).
        do {
            _ = try await scp.trustVerifyAttestation(
                contextId: "ctx-ffi-1",
                attestation: makeAttestationEnvelope()
            )
            XCTFail("an unresolvable issuer key must be an error, not a verdict")
        } catch let ScpError.Validation(msg, code) {
            XCTAssertEqual(code, "SCP-VALID-7052")
            XCTAssertTrue(msg.contains("did:dht:zIssuer"), msg)
        }
    }

    func testTrustVerifyAttestationResolvableIssuerBadSignatureIsInvalid() async throws {
        // An issuer that resolves on this instance reaches the real verifier:
        // a dummy signature yields a structured `valid: false` verdict.
        let issuer = try await createInMemoryIdentity(scp)
        let result = try await scp.trustVerifyAttestation(
            contextId: "ctx-ffi-1",
            attestation: makeAttestationEnvelope(issuer: issuer.did())
        )
        XCTAssertFalse(result.valid)
        XCTAssertTrue(result.errorMessage.contains("signature"), result.errorMessage)
    }

    /// A protocol suite one case short of its standard's minimum is refused.
    func testTrustCreateChallengeBelowMinimumIsValid7039() async throws {
        let verifier = try await createInMemoryIdentity(scp)
        let subject = try await createInMemoryIdentity(scp)
        let contextId = try await requiringContext(verifierDid: verifier.did())
        await assertValidationCode(challengeSuiteBelowMinimumCode) {
            _ = try await self.scp.trustCreateChallenge(
                verifier: verifier, subject: subject.did(), capabilityUri: schemaUri,
                testCases: makeTestCases(19), contextId: contextId, windowSecs: 3600
            )
        }
    }

    /// Test 38: one challenge from creation to admission through the real
    /// bridge. The context's governance requires the capability, so the
    /// subject is refused before it holds a record and admitted after.
    func test_challenge_round_trip() async throws {
        let verifier = try await createInMemoryIdentity(scp)
        let subject = try await createInMemoryIdentity(scp)
        let contextId = try await requiringContext(verifierDid: verifier.did())
        let cases = makeTestCases(20)

        let request = try await gradableChallenge(verifier, subject.did(), cases, contextId)
        XCTAssertEqual(request.verifier, verifier.did())
        XCTAssertEqual(request.subject, subject.did())
        XCTAssertEqual(request.contextId, contextId)
        XCTAssertEqual(request.capabilityUri, schemaUri)
        XCTAssertEqual(request.testCases.map(\.testId), cases.map(\.testId))
        XCTAssertEqual(request.expiresAt - request.createdAt, 3600)
        // The request commits to each answer and never carries it.
        XCTAssertFalse(try encodeChallengeRequestJson(request).contains("ExactMatch"))

        await assertValidationCode("SCP-VALID-7076") {
            try await self.scp.checkCapabilityRequirements(
                contextId: contextId, subjectDid: subject.did(),
                agentCapabilities: [], challengeVerifications: []
            )
        }

        let response = try await scp.trustRespondToChallenge(
            subject: subject, request: request, outputs: passingOutputs(cases), attempt: 1
        )
        XCTAssertEqual(response.challengeId, request.challengeId)
        XCTAssertEqual(response.subject, subject.did())
        XCTAssertEqual(response.attempt, 1)

        let graded = try await scp.trustGradeResponse(verifier: verifier, request: request, response: response)
        XCTAssertNil(graded.trustStoreError)
        XCTAssertEqual(graded.caseResults.count, 20)
        XCTAssertTrue(graded.caseResults.allSatisfy(\.passed))
        let record = graded.record
        XCTAssertTrue(record.passed)
        XCTAssertEqual(record.attempt, 1)
        XCTAssertEqual(record.passCount, 20)
        XCTAssertEqual(record.testCount, 20)
        XCTAssertEqual(record.challengeId, request.challengeId)
        XCTAssertEqual(record.verifier, verifier.did())
        XCTAssertEqual(record.subject, subject.did())
        XCTAssertEqual(record.contextId, contextId)

        try await scp.checkCapabilityRequirements(
            contextId: contextId, subjectDid: subject.did(),
            agentCapabilities: [], challengeVerifications: [record]
        )
        // Every field is signed: a record whose attempt was altered is dropped.
        await assertValidationCode("SCP-VALID-7076") {
            try await self.scp.checkCapabilityRequirements(
                contextId: contextId, subjectDid: subject.did(),
                agentCapabilities: [], challengeVerifications: [record.withAttempt(2)]
            )
        }
    }

    /// A response with a forged signature is refused and uses no attempt.
    func testForgedResponseIsRefusedAndGradesNothing() async throws {
        let verifier = try await createInMemoryIdentity(scp)
        let subject = try await createInMemoryIdentity(scp)
        let contextId = try await requiringContext(verifierDid: verifier.did())
        let cases = makeTestCases(20)
        let request = try await gradableChallenge(verifier, subject.did(), cases, contextId)
        let response = try await scp.trustRespondToChallenge(
            subject: subject, request: request, outputs: passingOutputs(cases), attempt: 1
        )
        let forged = ChallengeResponse(
            challengeId: response.challengeId, requestDigest: response.requestDigest,
            subject: response.subject, attempt: response.attempt, outputs: response.outputs,
            subjectSignature: Array(repeating: 0, count: 64)
        )
        do {
            _ = try await scp.trustGradeResponse(verifier: verifier, request: request, response: forged)
            XCTFail("a response with a forged signature must be refused")
        } catch is ScpError {}
        // The forgery took no attempt: the real response still grades as attempt 1.
        let graded = try await scp.trustGradeResponse(verifier: verifier, request: request, response: response)
        XCTAssertEqual(graded.record.attempt, 1)
        XCTAssertTrue(graded.record.passed)
    }
}

private extension ChallengeVerification {
    /// This record with `attempt` replaced and every other field, the
    /// signature included, kept.
    func withAttempt(_ attempt: UInt32) -> ChallengeVerification {
        ChallengeVerification(
            verificationId: verificationId, verifier: verifier, subject: subject,
            capabilityUri: capabilityUri, definitionDigest: definitionDigest,
            suiteDigest: suiteDigest, challengeId: challengeId, attempt: attempt,
            responseDigest: responseDigest, maxRetries: maxRetries,
            cooldownSecs: cooldownSecs, passThresholdBps: passThresholdBps,
            minCategoryCases: minCategoryCases, passed: passed, score: score,
            testCount: testCount, passCount: passCount,
            challengeCreatedAt: challengeCreatedAt, challengeExpiresAt: challengeExpiresAt,
            timestamp: timestamp, expiresAt: expiresAt, contextId: contextId,
            verifierSignature: verifierSignature
        )
    }
}
