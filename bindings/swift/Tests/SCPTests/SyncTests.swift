import Foundation
@testable import SCP
import Testing

// MARK: - Sync Tests

/// Tests for sync/offline classification operations via injectable bridge
/// closures.
///
/// See ADR-029 in `.docs/adrs/phase-6.md`.
struct SyncTests {
    // MARK: - classifyOffline via injectable bridge (roundtrip)

    @Test("classifyOffline calls bridge and returns tier string")
    func classifyOfflineRoundtrip() {
        var receivedLastContact: UInt64?
        var receivedNow: UInt64?

        let mockClassify: SyncBridge.ClassifyOfflineFn = { lastRelayContact, now in
            receivedLastContact = lastRelayContact
            receivedNow = now
            let elapsed = now - lastRelayContact
            if elapsed < 14400 { return "short" }
            if elapsed < 604_800 { return "extended" }
            return "long"
        }

        let tier = classifyOffline(
            lastRelayContact: 1_000_000,
            now: 1_001_000,
            classifyOfflineFn: mockClassify
        )

        #expect(tier == "short")
        #expect(receivedLastContact == 1_000_000)
        #expect(receivedNow == 1_001_000)
    }

    @Test("classifyOffline returns extended for 4h-7d gap")
    func classifyOfflineExtended() {
        let mockClassify: SyncBridge.ClassifyOfflineFn = { lastRelayContact, now in
            let elapsed = now - lastRelayContact
            if elapsed < 14400 { return "short" }
            if elapsed < 604_800 { return "extended" }
            return "long"
        }

        // 24 hours = 86400 seconds
        let tier = classifyOffline(
            lastRelayContact: 1_000_000,
            now: 1_086_400,
            classifyOfflineFn: mockClassify
        )

        #expect(tier == "extended")
    }

    @Test("classifyOffline returns long for >7d gap")
    func classifyOfflineLong() {
        let mockClassify: SyncBridge.ClassifyOfflineFn = { lastRelayContact, now in
            let elapsed = now - lastRelayContact
            if elapsed < 14400 { return "short" }
            if elapsed < 604_800 { return "extended" }
            return "long"
        }

        // 8 days = 691200 seconds
        let tier = classifyOffline(
            lastRelayContact: 1_000_000,
            now: 1_691_200,
            classifyOfflineFn: mockClassify
        )

        #expect(tier == "long")
    }

    // MARK: - classifyOfflineCustom via injectable bridge (roundtrip)

    @Test("classifyOfflineCustom calls bridge with custom thresholds")
    func classifyOfflineCustomRoundtrip() {
        var receivedTier1: UInt64?
        var receivedTier2: UInt64?

        let mockClassifyCustom: SyncBridge.ClassifyOfflineCustomFn = { lastRelayContact, now, tier1Threshold, tier2Threshold in
            receivedTier1 = tier1Threshold
            receivedTier2 = tier2Threshold
            let elapsed = now - lastRelayContact
            if elapsed < tier1Threshold { return "short" }
            if elapsed < tier2Threshold { return "extended" }
            return "long"
        }

        let tier = classifyOfflineCustom(
            lastRelayContact: 1_000_000,
            now: 1_000_500,
            tier1ThresholdSecs: 3600,
            tier2ThresholdSecs: 86400,
            classifyOfflineCustomFn: mockClassifyCustom
        )

        #expect(tier == "short")
        #expect(receivedTier1 == 3600)
        #expect(receivedTier2 == 86400)
    }

    @Test("classifyOfflineCustom returns long when exceeding tier2 threshold")
    func classifyOfflineCustomLong() {
        let mockClassifyCustom: SyncBridge.ClassifyOfflineCustomFn = { lastRelayContact, now, tier1Threshold, tier2Threshold in
            let elapsed = now - lastRelayContact
            if elapsed < tier1Threshold { return "short" }
            if elapsed < tier2Threshold { return "extended" }
            return "long"
        }

        let tier = classifyOfflineCustom(
            lastRelayContact: 1_000_000,
            now: 1_100_000,
            tier1ThresholdSecs: 1800,
            tier2ThresholdSecs: 7200,
            classifyOfflineCustomFn: mockClassifyCustom
        )

        #expect(tier == "long")
    }

    // MARK: - getSyncPolicy via injectable bridge (roundtrip)

    @Test("getSyncPolicy calls bridge and returns policy JSON")
    func getSyncPolicyRoundtrip() async throws {
        var receivedContextId: String?

        let mockGetPolicy: SyncBridge.GetPolicyFn = { contextId in
            receivedContextId = contextId
            return #"{"tier1_threshold_secs":14400,"tier2_threshold_secs":604800}"#
        }

        let result = try await getSyncPolicy(
            contextId: "ctx-sync-001",
            getPolicyFn: mockGetPolicy
        )

        #expect(result.contains("tier1_threshold_secs"))
        #expect(result.contains("14400"))
        #expect(receivedContextId == "ctx-sync-001")
    }

    @Test("getSyncPolicy propagates bridge errors")
    func getSyncPolicyPropagatesErrors() async throws {
        let mockGetPolicy: SyncBridge.GetPolicyFn = { _ in
            throw ScpError.Context(
                message: "context not found",
                code: "SCP-CTX-2041"
            )
        }

        do {
            _ = try await getSyncPolicy(
                contextId: "ctx-nonexistent",
                getPolicyFn: mockGetPolicy
            )
            Issue.record("Expected getSyncPolicy to throw")
        } catch let error as ScpError {
            if case let .Context(_, code) = error {
                #expect(code == "SCP-CTX-2041")
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("getSyncPolicy default throws descriptive error")
    func getSyncPolicyDefaultThrows() async throws {
        do {
            _ = try await getSyncPolicy(contextId: "ctx-default")
            Issue.record("Expected default to throw")
        } catch let error as ScpError {
            if case let .Context(message, code) = error {
                #expect(code == "SCP-CTX-2040")
                #expect(message.contains("not yet available"))
            } else {
                Issue.record("Expected ScpError.Context, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }
} // end SyncTests
