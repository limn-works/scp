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
private func makeAttestationEnvelope() -> CachedAttestationEnvelope {
    CachedAttestationEnvelope(
        id: "att-1",
        attestationType: "AgentCapability",
        issuer: "did:dht:zIssuer",
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
    expected: ExpectedOutput = .exactMatch(value: ["ok": true])
) -> ChallengeRequest {
    ChallengeRequest(
        challengeId: challengeId,
        capabilityUri: schemaUri,
        testCases: [
            TestCase(testId: "t0", input: ["i": 0], expected: expected, category: "basic", weight: 10000)
        ],
        timeoutSecs: 300,
        verifier: "did:dht:zVerifier",
        subject: "did:dht:zSubject",
        verifierSignature: signature
    )
}

/// A structurally-valid `ChallengeResponse` with a real 64-byte signature.
private func makeChallengeResponse(
    signature: [UInt8] = Array(repeating: 4, count: 64)
) -> ChallengeResponse {
    ChallengeResponse(
        challengeId: String(repeating: "ab", count: 32),
        responderDid: "did:dht:zSubject",
        result: ["passed": true],
        completedAt: 1_700_000_100,
        signature: signature
    )
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

    func testChallengeRequestEncodesSevenSnakeCaseFields() throws {
        let json = try encodeChallengeRequestJson(makeChallengeRequest())
        assertJSONEqual(
            json,
            """
            {
              "challenge_id": "\(String(repeating: "ab", count: 32))",
              "capability_uri": "scp:capability:schema-validation/v1",
              "test_cases": [{"test_id": "t0", "input": {"i": 0},
                "expected": {"ExactMatch": {"value": {"ok": true}}},
                "category": "basic", "weight": 10000}],
              "timeout_secs": 300,
              "verifier": "did:dht:zVerifier",
              "subject": "did:dht:zSubject",
              "verifier_signature": \(Array(repeating: 8, count: 64))
            }
            """
        )
    }

    func testEveryExpectedOutputVariantEncodesTaggedAndDecodesBack() throws {
        let variants: [(ExpectedOutput, String)] = [
            (.exactMatch(value: [1, "a"]), #"{"ExactMatch":{"value":[1,"a"]}}"#),
            (.schemaMatch(schema: ["type": "object"]), #"{"SchemaMatch":{"schema":{"type":"object"}}}"#),
            (.containsAll(required: ["a", "b"]), #"{"ContainsAll":{"required":["a","b"]}}"#),
            (.containsNone(forbidden: ["x"]), #"{"ContainsNone":{"forbidden":["x"]}}"#),
            (.customEval(evaluatorOutletId: "o-1"), #"{"CustomEval":{"evaluator_outlet_id":"o-1"}}"#)
        ]
        for (expected, wire) in variants {
            let request = makeChallengeRequest(expected: expected)
            let casesJson = try encodeTestCasesJson(request.testCases)
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
            XCTAssertEqual(try decodeChallengeRequestJson(encodeChallengeRequestJson(request)), request)
        }
    }

    func testChallengeRequestDecodeRefusesAnUnknownVariant() throws {
        let json = try encodeChallengeRequestJson(makeChallengeRequest())
            .replacingOccurrences(of: "\"ExactMatch\"", with: "\"Nope\"")
        XCTAssertThrowsError(try decodeChallengeRequestJson(json)) { error in
            guard case let ScpError.Validation(_, code) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(code, "SCP-VALID-7098")
        }
    }

    func testChallengeResponseEncodesFiveSnakeCaseFields() throws {
        let json = try encodeChallengeResponseJson(makeChallengeResponse())
        assertJSONEqual(
            json,
            """
            {
              "challenge_id": "\(String(repeating: "ab", count: 32))",
              "responder_did": "did:dht:zSubject",
              "result": {"passed": true},
              "completed_at": 1700000100,
              "signature": \(Array(repeating: 4, count: 64))
            }
            """
        )
    }

    func testWrongLengthChallengeSignaturesThrowBeforeBridgeCall() throws {
        XCTAssertThrowsError(
            try encodeChallengeRequestJson(makeChallengeRequest(signature: [1, 2, 3]))
        ) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(msg, "ChallengeRequest.verifierSignature must be exactly 64 elements, got 3")
        }
        XCTAssertThrowsError(
            try encodeChallengeRequestJson(makeChallengeRequest(challengeId: "chal-1"))
        ) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(msg, "ChallengeRequest.challengeId must be 64 lowercase hex characters")
        }
        XCTAssertThrowsError(
            try encodeChallengeResponseJson(
                makeChallengeResponse(signature: Array(repeating: 4, count: 63))
            )
        ) { error in
            guard case let ScpError.Validation(msg, _) = error else {
                return XCTFail("expected ScpError.Validation, got \(error)")
            }
            XCTAssertEqual(msg, "ChallengeResponse.signature must be exactly 64 elements, got 63")
        }
    }
}

/// Call-through against the real Rust deserializers: these invoke the bridge
/// verification ops through the typed wrappers, proving the serialized JSON
/// parses and evaluates on the Rust side (dummy signatures yield structured
/// negative verdicts, never parse errors).
final class ChallengeTrustInputCallThroughTests: XCTestCase {
    func testTrustVerifyAttestationTypedEnvelopeReachesVerifier() async throws {
        // The dummy signature cannot verify — a structured `valid: false`
        // (not a thrown parse error) proves the envelope reached the real
        // verifier.
        let scp = try SCP(storage: .inMemory)
        let result = try await scp.trustVerifyAttestation(
            contextId: "ctx-ffi-1",
            attestation: makeAttestationEnvelope()
        )
        XCTAssertFalse(result.valid)
        XCTAssertFalse(result.errorMessage.isEmpty)
    }

    func testTrustCreateChallengeBelowMinimumIsValid7039() async throws {
        let scp = try SCP(storage: .inMemory)
        let verifier = try await createInMemoryIdentity(scp)
        let subject = try await createInMemoryIdentity(scp)
        do {
            _ = try await scp.trustCreateChallenge(
                verifier: verifier, subject: subject.did(), capabilityUri: schemaUri,
                testCases: makeTestCases(19)
            )
            XCTFail("a 19-case schema-validation suite must be refused")
        } catch let ScpError.Validation(_, code) {
            XCTAssertEqual(code, challengeSuiteBelowMinimumCode)
        }
    }

    func testCreatedChallengeDecodesAndAForgedResponseIsRefused() async throws {
        let scp = try SCP(storage: .inMemory)
        let verifier = try await createInMemoryIdentity(scp)
        let subject = try await createInMemoryIdentity(scp)
        let cases = makeTestCases(20)
        let created = try await scp.trustCreateChallenge(
            verifier: verifier, subject: subject.did(), capabilityUri: schemaUri, testCases: cases
        )
        let challenge = try decodeChallengeRequestJson(created.challengeJson)
        XCTAssertEqual(challenge.challengeId, created.challengeId)
        XCTAssertEqual(challenge.verifier, verifier.did())
        XCTAssertEqual(challenge.subject, subject.did())
        XCTAssertEqual(challenge.testCases, cases)

        let response = ChallengeResponse(
            challengeId: challenge.challengeId,
            responderDid: subject.did(),
            result: ["passed": true, "score": 10000, "test_count": 20, "pass_count": 20],
            completedAt: UInt64(Date().timeIntervalSince1970),
            signature: Array(repeating: 0, count: 64)
        )
        do {
            _ = try await scp.trustVerifyResponse(
                verifier: verifier, challenge: challenge, response: response, contextId: "ctx-ffi"
            )
            XCTFail("a response with a forged signature must be refused")
        } catch let ScpError.Validation(_, code) {
            XCTAssertEqual(code, "SCP-VALID-7003")
        }
    }
}
