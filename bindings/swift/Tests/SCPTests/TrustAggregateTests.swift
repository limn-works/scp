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

/// A structurally-valid `ChallengeRequest` with a real 64-byte signature.
private func makeChallengeRequest(
    signature: [UInt8] = Array(repeating: 8, count: 64)
) -> ChallengeRequest {
    ChallengeRequest(
        challengeId: "chal-1",
        challengeType: "scp:capability:schema-validation/v1",
        challengerDid: "did:dht:zChallenger",
        subjectDid: "did:dht:zSubject",
        capabilityUri: "scp:capability:schema-validation/v1",
        parameters: ["schema": "object"],
        timeout: CachedAttestationDuration(secs: 300, nanos: 0),
        signature: signature
    )
}

/// A structurally-valid `ChallengeResponse` with a real 64-byte signature.
private func makeChallengeResponse(
    signature: [UInt8] = Array(repeating: 4, count: 64)
) -> ChallengeResponse {
    ChallengeResponse(
        challengeId: "chal-1",
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

    func testChallengeRequestEncodesEightSnakeCaseFields() throws {
        let json = try encodeChallengeRequestJson(makeChallengeRequest())
        assertJSONEqual(
            json,
            """
            {
              "challenge_id": "chal-1",
              "challenge_type": "scp:capability:schema-validation/v1",
              "challenger_did": "did:dht:zChallenger",
              "subject_did": "did:dht:zSubject",
              "capability_uri": "scp:capability:schema-validation/v1",
              "parameters": {"schema": "object"},
              "timeout": {"secs": 300, "nanos": 0},
              "signature": \(Array(repeating: 8, count: 64))
            }
            """
        )
    }

    func testChallengeResponseEncodesFiveSnakeCaseFields() throws {
        let json = try encodeChallengeResponseJson(makeChallengeResponse())
        assertJSONEqual(
            json,
            """
            {
              "challenge_id": "chal-1",
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
            XCTAssertEqual(msg, "ChallengeRequest.signature must be exactly 64 elements, got 3")
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
    func testTrustVerifyAttestationTypedEnvelopeReachesVerifier() throws {
        // The dummy signature cannot verify — a structured `valid: false`
        // (not a thrown parse error) proves the envelope reached the real
        // verifier.
        let result = try trustVerifyAttestation(attestation: makeAttestationEnvelope())
        XCTAssertFalse(result.valid)
        XCTAssertFalse(result.errorMessage.isEmpty)
    }

    func testTrustVerifyResponseTypedPairReachesVerifier() throws {
        // Dummy signatures cannot verify — the structured `false` (not a
        // thrown parse error) proves both records reached the real verifier.
        let scp = try SCP(storage: .inMemory)
        let valid = try scp.trustVerifyResponse(
            challenge: makeChallengeRequest(),
            response: makeChallengeResponse()
        )
        XCTAssertFalse(valid)
    }
}
