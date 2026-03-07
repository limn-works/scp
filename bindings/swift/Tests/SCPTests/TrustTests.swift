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

    // MARK: - TrustEvaluation from TrustScoreResult

    @Test("TrustEvaluation initializes from TrustScoreResult")
    func trustEvaluationFromScoreResult() {
        let score = TrustScoreResult(
            messageCount: 42,
            governanceCount: 3,
            compositeScore: 0.85
        )

        let eval = TrustEvaluation(from: score)

        #expect(eval.tokensValid)
        #expect(eval.signaturesValid)
        #expect(eval.withinCeiling)
        #expect(eval.notRevoked)
        #expect(eval.behavioralRecord?.governanceActionsAgainst == 3)
        #expect(eval.verifiedAttestationCount == 0)
    }

    // MARK: - queryTrustScore via injectable bridge

    @Test("queryTrustScore calls bridge and returns score result")
    func queryTrustScoreRoundtrip() throws {
        var receivedDid: String?
        var receivedContextId: String?

        let mockQueryScore: TrustBridge.QueryScoreFn = { did, contextId in
            receivedDid = did
            receivedContextId = contextId
            return TrustScoreResult(
                messageCount: 100,
                governanceCount: 5,
                compositeScore: 0.75
            )
        }

        let result = try queryTrustScore(
            did: "did:dht:z6MkScorer",
            contextId: "ctx-score-001",
            queryScoreFn: mockQueryScore
        )

        #expect(receivedDid == "did:dht:z6MkScorer")
        #expect(receivedContextId == "ctx-score-001")
        #expect(result.messageCount == 100)
        #expect(result.governanceCount == 5)
        #expect(result.compositeScore == 0.75)
    }

    // MARK: - verifyAttestation via injectable bridge

    @Test("verifyAttestation calls bridge with JSON and returns result")
    func verifyAttestationRoundtrip() throws {
        var receivedJson: String?

        let mockVerify: TrustBridge.VerifyAttestationFn = { json in
            receivedJson = json
            return AttestationVerificationResult(
                valid: true,
                chainDepth: 1,
                errorMessage: ""
            )
        }

        let result = try verifyAttestation(
            attestationJson: "{\"type\":\"test\"}",
            verifyAttestationFn: mockVerify
        )

        #expect(receivedJson == "{\"type\":\"test\"}")
        #expect(result.valid)
        #expect(result.chainDepth == 1)
        #expect(result.errorMessage == "")
    }

    @Test("verifyAttestation returns invalid result for bad attestation")
    func verifyAttestationInvalid() throws {
        let mockVerify: TrustBridge.VerifyAttestationFn = { _ in
            return AttestationVerificationResult(
                valid: false,
                chainDepth: 0,
                errorMessage: "signature verification failed"
            )
        }

        let result = try verifyAttestation(
            attestationJson: "{\"bad\":\"data\"}",
            verifyAttestationFn: mockVerify
        )

        #expect(!result.valid)
        #expect(result.chainDepth == 0)
        #expect(result.errorMessage == "signature verification failed")
    }

    // MARK: - createChallenge via injectable bridge

    @Test("createChallenge calls bridge and returns challenge result")
    func createChallengeRoundtrip() throws {
        var receivedTargetDid: String?

        let mockCreate: TrustBridge.CreateChallengeFn = { targetDid in
            receivedTargetDid = targetDid
            return ChallengeResult(
                challengeId: "challenge-uuid-001",
                challengeJson: "{\"target\":\"did:dht:z6MkTarget\"}"
            )
        }

        let result = try createChallenge(
            targetDid: "did:dht:z6MkTarget",
            createChallengeFn: mockCreate
        )

        #expect(receivedTargetDid == "did:dht:z6MkTarget")
        #expect(result.challengeId == "challenge-uuid-001")
        #expect(result.challengeJson.contains("did:dht:z6MkTarget"))
    }

    // MARK: - verifyChallengeResponse via injectable bridge

    @Test("verifyChallengeResponse calls bridge and returns bool")
    func verifyChallengeResponseRoundtrip() throws {
        var receivedChallengeJson: String?
        var receivedResponseJson: String?

        let mockVerify: TrustBridge.VerifyResponseFn = { challengeJson, responseJson in
            receivedChallengeJson = challengeJson
            receivedResponseJson = responseJson
            return true
        }

        let result = try verifyChallengeResponse(
            challengeJson: "{\"challenge\":\"abc\"}",
            responseJson: "{\"response\":\"xyz\"}",
            verifyResponseFn: mockVerify
        )

        #expect(receivedChallengeJson == "{\"challenge\":\"abc\"}")
        #expect(receivedResponseJson == "{\"response\":\"xyz\"}")
        #expect(result)
    }

    @Test("verifyChallengeResponse returns false for invalid response")
    func verifyChallengeResponseInvalid() throws {
        let mockVerify: TrustBridge.VerifyResponseFn = { _, _ in
            return false
        }

        let result = try verifyChallengeResponse(
            challengeJson: "{\"challenge\":\"abc\"}",
            responseJson: "{\"wrong\":\"data\"}",
            verifyResponseFn: mockVerify
        )

        #expect(!result)
    }

} // end TrustTests
