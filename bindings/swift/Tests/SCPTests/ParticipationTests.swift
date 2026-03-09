import Foundation
@testable import SCP
import Testing

// MARK: - Participation Tests

/// Tests for participation requirement verification.
///
/// ``verifyParticipationRequirements`` is a pure Swift function (no bridge
/// dependency). It has real logic — conjunction of threshold checks with
/// missing-key-is-zero semantics — so we test it thoroughly.
///
/// See ADR-017 Layer 2 (Behavioral Validation) and spec section 23.7.
struct ParticipationTests {
    // MARK: - ParticipationFact enum

    @Test("ParticipationFact has correct raw values")
    func participationFactRawValues() {
        #expect(ParticipationFact.messagesSent.rawValue == "messages_sent")
        #expect(ParticipationFact.toolsInvoked.rawValue == "tools_invoked")
        #expect(ParticipationFact.governanceActions.rawValue == "governance_actions")
        #expect(ParticipationFact.contextsParticipated.rawValue == "contexts_participated")
        #expect(ParticipationFact.attestationsVerified.rawValue == "attestations_verified")
    }

    @Test("ParticipationFact has 5 cases")
    func participationFactCaseCount() {
        #expect(ParticipationFact.allCases.count == 5)
    }

    // MARK: - ParticipationThreshold type shape

    @Test("ParticipationThreshold stores fact and minimum")
    func participationThresholdFields() {
        let threshold = ParticipationThreshold(
            fact: .messagesSent,
            minimum: 10
        )
        #expect(threshold.fact == .messagesSent)
        #expect(threshold.minimum == 10)
    }

    // MARK: - RequireParticipation type shape

    @Test("RequireParticipation stores thresholds array")
    func requireParticipationFields() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 5),
            ParticipationThreshold(fact: .toolsInvoked, minimum: 2)
        ])
        #expect(requirement.thresholds.count == 2)
    }

    // MARK: - verifyParticipationRequirements (core logic)

    @Test("verifyParticipationRequirements passes when all thresholds met")
    func allThresholdsMet() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 5),
            ParticipationThreshold(fact: .toolsInvoked, minimum: 2)
        ])
        let profile: ParticipationProfile = [
            .messagesSent: 10,
            .toolsInvoked: 3
        ]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(result)
    }

    @Test("verifyParticipationRequirements fails when one threshold not met")
    func oneThresholdNotMet() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 5),
            ParticipationThreshold(fact: .toolsInvoked, minimum: 10)
        ])
        let profile: ParticipationProfile = [
            .messagesSent: 10,
            .toolsInvoked: 3
        ]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(!result)
    }

    @Test("verifyParticipationRequirements treats missing profile key as zero")
    func missingProfileKeyIsZero() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 1)
        ])
        let profile: ParticipationProfile = [:]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(!result)
    }

    @Test("verifyParticipationRequirements passes with empty thresholds")
    func emptyThresholdsPasses() {
        let requirement = RequireParticipation(thresholds: [])
        let profile: ParticipationProfile = [:]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(result)
    }

    @Test("verifyParticipationRequirements passes when value equals minimum")
    func exactMinimumPasses() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 5)
        ])
        let profile: ParticipationProfile = [
            .messagesSent: 5
        ]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(result)
    }

    @Test("verifyParticipationRequirements fails when value is one below minimum")
    func oneBelowMinimumFails() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 5)
        ])
        let profile: ParticipationProfile = [
            .messagesSent: 4
        ]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(!result)
    }

    @Test("verifyParticipationRequirements passes with zero minimum and missing key")
    func zeroMinimumWithMissingKey() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .governanceActions, minimum: 0)
        ])
        let profile: ParticipationProfile = [:]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(result)
    }

    @Test("verifyParticipationRequirements handles all five fact types")
    func allFiveFactTypes() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 1),
            ParticipationThreshold(fact: .toolsInvoked, minimum: 1),
            ParticipationThreshold(fact: .governanceActions, minimum: 1),
            ParticipationThreshold(fact: .contextsParticipated, minimum: 1),
            ParticipationThreshold(fact: .attestationsVerified, minimum: 1)
        ])
        let profile: ParticipationProfile = [
            .messagesSent: 10,
            .toolsInvoked: 5,
            .governanceActions: 2,
            .contextsParticipated: 3,
            .attestationsVerified: 1
        ]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(result)
    }

    @Test("verifyParticipationRequirements extra profile keys do not interfere")
    func extraProfileKeysIgnored() {
        let requirement = RequireParticipation(thresholds: [
            ParticipationThreshold(fact: .messagesSent, minimum: 1)
        ])
        let profile: ParticipationProfile = [
            .messagesSent: 10,
            .toolsInvoked: 5,
            .governanceActions: 2
        ]

        let result = verifyParticipationRequirements(
            requirement: requirement,
            profile: profile
        )

        #expect(result)
    }
} // end ParticipationTests
