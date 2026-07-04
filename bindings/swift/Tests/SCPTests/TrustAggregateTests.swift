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
            "IdentityLink", "CapabilityDelegation", "ToolIntegrity", "AgentCapability",
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
