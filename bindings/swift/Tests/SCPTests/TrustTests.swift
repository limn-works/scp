@testable import SCP
import XCTest

// Tests for the Swift trust-signal SDK wrappers (ADR-059, spec §7.2.4/§7.3.2).
//
// These exercise the PURE projection/serialization logic that sits on top of
// the UniFFI bridge — mapping the typed `CapabilityValidationRecord` /
// `ParticipationRecordView` onto the idiomatic Swift `CapabilityValidation` /
// `BehavioralRecord`, the `allValid` collapse, the empty-log zeroed record, and
// the cached-attestation wire serialization. None of these require the linked
// Rust binary (the records are plain data structs), so they run in this
// environment. The full `SCP.evaluateTrust` / `SCP.ucanEvaluate` /
// `SCP.participationRecord` round-trips dispatch through `inner` and require the
// XCFramework (SCP-103); their projection halves are covered here.

final class TrustTests: XCTestCase {
    // MARK: - CapabilityValidation

    /// `ucanEvaluate`'s projection maps the six UniFFI booleans onto the SDK
    /// type one-for-one — the structured per-stage breakdown, never prose.
    func testCapabilityValidationProjectsSixBooleans() {
        let record = CapabilityValidationRecord(
            tokensValid: true,
            signaturesValid: false,
            withinCeiling: true,
            nonceValid: false,
            notRevoked: true,
            timeBoundsValid: false
        )
        let validation = CapabilityValidation(record: record)
        XCTAssertTrue(validation.tokensValid)
        XCTAssertFalse(validation.signaturesValid)
        XCTAssertTrue(validation.withinCeiling)
        XCTAssertFalse(validation.nonceValid)
        XCTAssertTrue(validation.notRevoked)
        XCTAssertFalse(validation.timeBoundsValid)
    }

    /// `allValid` is the AND of all six stages — `true` only when every stage
    /// passed.
    func testAllValidIsConjunctionOfStages() {
        let allTrue = CapabilityValidation(
            tokensValid: true,
            signaturesValid: true,
            withinCeiling: true,
            nonceValid: true,
            notRevoked: true,
            timeBoundsValid: true
        )
        XCTAssertTrue(allTrue.allValid)

        // A single failing stage collapses the whole conjunction.
        let oneFalse = CapabilityValidation(
            tokensValid: true,
            signaturesValid: true,
            withinCeiling: true,
            nonceValid: false,
            notRevoked: true,
            timeBoundsValid: true
        )
        XCTAssertFalse(oneFalse.allValid)
    }

    // MARK: - BehavioralRecord

    /// `participationRecord`'s projection maps all twelve §7.3.2 facts.
    func testBehavioralRecordProjectsTwelveFields() {
        let view = ParticipationRecordView(
            subjectDid: "did:key:zSubject",
            participationDurationSecs: 3600,
            governanceActionsAgainst: 1,
            governanceActionsBy: 2,
            toolInvocationCount: 5,
            toolInvocationCountAnchored: false,
            contextCreationCount: 1,
            roleProgressionCount: 3,
            attestationCount: 4,
            attestationCountAnchored: false,
            computedAt: 1_700_000_000,
            eventLogRoot: "abc123"
        )
        let record = BehavioralRecord(record: view)
        XCTAssertEqual(record.subjectDid, "did:key:zSubject")
        XCTAssertEqual(record.participationDurationSecs, 3600)
        XCTAssertEqual(record.governanceActionsAgainst, 1)
        XCTAssertEqual(record.governanceActionsBy, 2)
        XCTAssertEqual(record.toolInvocationCount, 5)
        XCTAssertFalse(record.toolInvocationCountAnchored)
        XCTAssertEqual(record.contextCreationCount, 1)
        XCTAssertEqual(record.roleProgressionCount, 3)
        XCTAssertEqual(record.attestationCount, 4)
        XCTAssertFalse(record.attestationCountAnchored)
        XCTAssertEqual(record.computedAt, 1_700_000_000)
        XCTAssertEqual(record.eventLogRoot, "abc123")
    }

    /// The empty-log (`SCP-CTX-2076`) record is fully zeroed but carries the
    /// subject DID — identical in shape to the Python/TypeScript SDKs.
    func testZeroedBehavioralRecord() {
        let record = BehavioralRecord.zeroed(subjectDid: "did:key:zSubject")
        XCTAssertEqual(record.subjectDid, "did:key:zSubject")
        XCTAssertEqual(record.participationDurationSecs, 0)
        XCTAssertEqual(record.governanceActionsAgainst, 0)
        XCTAssertEqual(record.governanceActionsBy, 0)
        XCTAssertEqual(record.toolInvocationCount, 0)
        XCTAssertFalse(record.toolInvocationCountAnchored)
        XCTAssertEqual(record.contextCreationCount, 0)
        XCTAssertEqual(record.roleProgressionCount, 0)
        XCTAssertEqual(record.attestationCount, 0)
        XCTAssertFalse(record.attestationCountAnchored)
        XCTAssertEqual(record.computedAt, 0)
        XCTAssertEqual(record.eventLogRoot, "")
    }

    /// The no-participation-facts code matches the bridge's structured code so
    /// `evaluateTrust` branches on it, never on prose.
    func testNoParticipationFactsCode() {
        XCTAssertEqual(noParticipationFactsCode, "SCP-CTX-2076")
    }

    // MARK: - TrustEvaluation

    /// A `TrustEvaluation` carries the resolved context label and both layers.
    func testTrustEvaluationShape() {
        let evaluation = TrustEvaluation(
            subjectDid: "did:key:zSubject",
            contextId: "ctx-resolved",
            capabilityValidation: CapabilityValidation(
                tokensValid: true,
                signaturesValid: true,
                withinCeiling: true,
                nonceValid: true,
                notRevoked: true,
                timeBoundsValid: true
            ),
            behavioralRecord: BehavioralRecord.zeroed(subjectDid: "did:key:zSubject")
        )
        XCTAssertEqual(evaluation.subjectDid, "did:key:zSubject")
        XCTAssertEqual(evaluation.contextId, "ctx-resolved")
        XCTAssertTrue(evaluation.capabilityValidation.allValid)
        XCTAssertEqual(evaluation.behavioralRecord.subjectDid, "did:key:zSubject")
        XCTAssertTrue(evaluation.attestations.isEmpty)
    }

    // MARK: - Cached-attestation wire serialization

    /// A `CachedAttestation` serializes to the serde-canonical snake_case the
    /// bridge `participation_record` op deserializes.
    func testCachedAttestationSerializesToSnakeCaseWire() throws {
        let envelope = CachedAttestationEnvelope(
            id: "att-1",
            attestationType: "IdentityLink",
            issuer: "did:key:zIssuer",
            subject: "did:key:zSubject",
            claim: ["device": "iphone", "verified": true],
            issuedAt: 1_700_000_000,
            revocationStatus: ["NotRevoked": [:]],
            signature: Array(repeating: 0, count: 64),
            evidence: CachedAttestationEvidence(evidenceType: "manual", data: "ok"),
            expiresAt: 1_800_000_000
        )
        let cached = CachedAttestation(attestation: envelope, verifiedAt: 1_700_000_100, ttlSecs: 3600)

        let json = try encodeCachedAttestations([cached])
        guard let data = json.data(using: .utf8),
              let array = try JSONSerialization.jsonObject(with: data) as? [[String: Any]],
              let first = array.first,
              let att = first["attestation"] as? [String: Any] else {
            XCTFail("expected a JSON array of attestation objects")
            return
        }

        // Wrapper TTL metadata uses snake_case keys.
        XCTAssertEqual(first["verified_at"] as? Int, 1_700_000_100)
        XCTAssertEqual(first["ttl_secs"] as? Int, 3600)

        // Envelope fields use the serde-canonical snake_case names.
        XCTAssertEqual(att["id"] as? String, "att-1")
        XCTAssertEqual(att["attestation_type"] as? String, "IdentityLink")
        XCTAssertEqual(att["issued_at"] as? Int, 1_700_000_000)
        XCTAssertEqual(att["expires_at"] as? Int, 1_800_000_000)
        XCTAssertNotNil(att["claim"])
        XCTAssertNotNil(att["revocation_status"])
        let evidence = att["evidence"] as? [String: Any]
        XCTAssertEqual(evidence?["evidence_type"] as? String, "manual")
        XCTAssertEqual((att["signature"] as? [Any])?.count, 64)
    }

    /// An empty cached-attestation list serializes to `"[]"` — the bridge then
    /// reports only what its trust store already holds (verifier-relative).
    func testEmptyCachedAttestationsSerializeToEmptyArray() throws {
        let json = try encodeCachedAttestations([])
        XCTAssertEqual(json, "[]")
    }
}
