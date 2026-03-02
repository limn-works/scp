import Foundation
import Testing

@testable import SCP

// MARK: - Trust Tests

/// Tests for trust evaluation: TrustEvaluation type shape, BehavioralRecord,
/// TrustInput mapping, and async bridge roundtrip.
///
/// UniFFI TrustInput fields: subjectDid, contextId, verifiedAttestationCount,
///   participationCount, triggeredConsequences, evaluatedAt
///
/// No single UniFFI bridge function exists for trust evaluation. The Swift
/// layer composes trust data from TrustInput and structures it into the
/// four-layer trust model. The injectable bridge pattern allows testing
/// with mock inputs.
///
/// See ADR-017 (Trust Model), ADR-026 (Swift SDK), and story SCP-221.
@Suite("Trust Tests")
struct TrustTests {

    // MARK: - TrustEvaluation type shape

    @Test("TrustEvaluation stores all four-layer fields")
    func trustEvaluationFields() {
        let record = BehavioralRecord(
            contextsParticipated: 5,
            totalDurationSecs: 3_600,
            governanceActionsAgainst: 0,
            toolInvocations: 10,
            roleTransitions: 1
        )
        let eval = TrustEvaluation(
            tokensValid: true,
            signaturesValid: true,
            withinCeiling: true,
            notRevoked: true,
            behavioralRecord: record,
            verifiedAttestationCount: 3,
            challengeResultCount: 1,
            consequenceRuleCount: 2
        )

        #expect(eval.tokensValid)
        #expect(eval.signaturesValid)
        #expect(eval.withinCeiling)
        #expect(eval.notRevoked)
        #expect(eval.behavioralRecord != nil)
        #expect(eval.behavioralRecord?.contextsParticipated == 5)
        #expect(eval.verifiedAttestationCount == 3)
        #expect(eval.challengeResultCount == 1)
        #expect(eval.consequenceRuleCount == 2)
    }

    @Test("TrustEvaluation with nil behavioral record")
    func trustEvaluationNilBehavioral() {
        let eval = TrustEvaluation(
            tokensValid: true,
            signaturesValid: true,
            withinCeiling: false,
            notRevoked: true,
            behavioralRecord: nil,
            verifiedAttestationCount: 0,
            challengeResultCount: 0,
            consequenceRuleCount: 0
        )

        #expect(eval.behavioralRecord == nil)
        #expect(!eval.withinCeiling)
    }

    @Test("TrustEvaluation is Sendable")
    func trustEvaluationIsSendable() async {
        let eval: any Sendable = TrustEvaluation(
            tokensValid: true,
            signaturesValid: true,
            withinCeiling: true,
            notRevoked: true,
            behavioralRecord: nil,
            verifiedAttestationCount: 0,
            challengeResultCount: 0,
            consequenceRuleCount: 0
        )
        #expect(eval is TrustEvaluation)
    }

    // MARK: - BehavioralRecord type shape

    @Test("BehavioralRecord stores all fields")
    func behavioralRecordFields() {
        let record = BehavioralRecord(
            contextsParticipated: 10,
            totalDurationSecs: 86_400,
            governanceActionsAgainst: 2,
            toolInvocations: 50,
            roleTransitions: 3
        )

        #expect(record.contextsParticipated == 10)
        #expect(record.totalDurationSecs == 86_400)
        #expect(record.governanceActionsAgainst == 2)
        #expect(record.toolInvocations == 50)
        #expect(record.roleTransitions == 3)
    }

    @Test("BehavioralRecord is Sendable")
    func behavioralRecordIsSendable() async {
        let record: any Sendable = BehavioralRecord(
            contextsParticipated: 0,
            totalDurationSecs: 0,
            governanceActionsAgainst: 0,
            toolInvocations: 0,
            roleTransitions: 0
        )
        #expect(record is BehavioralRecord)
    }

    // MARK: - TrustEvaluation from TrustInput (UniFFI mapping)

    @Test("TrustEvaluation initializes from UniFFI TrustInput")
    func trustEvaluationFromTrustInput() {
        let input = TrustInput(
            subjectDid: "did:dht:z6MkSubject",
            contextId: "ctx-trust-001",
            verifiedAttestationCount: 5,
            participationCount: 12,
            triggeredConsequences: 1,
            evaluatedAt: 1_700_000_000
        )

        let eval = TrustEvaluation(from: input)

        #expect(eval.tokensValid)
        #expect(eval.signaturesValid)
        #expect(eval.withinCeiling)
        #expect(eval.notRevoked)
        #expect(eval.verifiedAttestationCount == 5)
        #expect(eval.consequenceRuleCount == 1)
        #expect(eval.behavioralRecord?.contextsParticipated == 12)
    }

    // MARK: - evaluateTrust via injectable bridge (async roundtrip)

    @Test("evaluateTrust calls bridge and returns evaluation")
    func evaluateTrustRoundtrip() async throws {
        var receivedSubjectDid: String?
        var receivedContextId: String?

        let mockEvaluate: TrustBridge.EvaluateFn = { subjectDid, contextId in
            receivedSubjectDid = subjectDid
            receivedContextId = contextId
            return TrustEvaluation(
                tokensValid: true,
                signaturesValid: true,
                withinCeiling: true,
                notRevoked: true,
                behavioralRecord: BehavioralRecord(
                    contextsParticipated: 7,
                    totalDurationSecs: 14_400,
                    governanceActionsAgainst: 0,
                    toolInvocations: 25,
                    roleTransitions: 2
                ),
                verifiedAttestationCount: 4,
                challengeResultCount: 1,
                consequenceRuleCount: 0
            )
        }

        let result = try await evaluateTrust(
            subjectDid: "did:dht:z6MkSubject",
            contextId: "ctx-trust-roundtrip",
            evaluateFn: mockEvaluate
        )

        #expect(receivedSubjectDid == "did:dht:z6MkSubject")
        #expect(receivedContextId == "ctx-trust-roundtrip")
        #expect(result.tokensValid)
        #expect(result.verifiedAttestationCount == 4)
        #expect(result.behavioralRecord?.contextsParticipated == 7)
    }

    @Test("evaluateTrust default bridge returns baseline evaluation")
    func evaluateTrustDefaultBridge() async throws {
        let result = try await evaluateTrust(
            subjectDid: "did:dht:z6MkSubject",
            contextId: "ctx-default"
        )

        #expect(result.tokensValid)
        #expect(result.signaturesValid)
        #expect(result.withinCeiling)
        #expect(result.notRevoked)
        #expect(result.verifiedAttestationCount == 0)
        #expect(result.consequenceRuleCount == 0)
    }

} // end TrustTests
