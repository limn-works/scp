import Foundation
@testable import SCP
import Testing

// MARK: - Provenance Tests

/// Tests for provenance operations: quality evaluation, chain depth checking,
/// and provenance attachment via injectable bridge closures.
///
/// See spec section 24 (Provenance System) and ADR-019.
struct ProvenanceTests {
    // MARK: - evaluateProvenanceQuality via injectable bridge (roundtrip)

    @Test("evaluateProvenanceQuality calls bridge and returns tier")
    func evaluateQualityRoundtrip() throws {
        var receivedSourceContext: String?
        var receivedSourceType: String?
        var receivedContextState: String?
        var receivedCounterparties: [String]?

        let mockEvaluate: ProvenanceBridge.EvaluateQualityFn = { sourceContext, sourceType, contextState, counterparties in
            receivedSourceContext = sourceContext
            receivedSourceType = sourceType
            receivedContextState = contextState
            receivedCounterparties = counterparties
            return 3
        }

        let tier = try evaluateProvenanceQuality(
            sourceContext: "ctx-source",
            sourceType: "persistent",
            contextState: "active",
            counterparties: ["did:dht:z6MkAlice"],
            evaluateQualityFn: mockEvaluate
        )

        #expect(tier == 3)
        #expect(receivedSourceContext == "ctx-source")
        #expect(receivedSourceType == "persistent")
        #expect(receivedContextState == "active")
        #expect(receivedCounterparties == ["did:dht:z6MkAlice"])
    }

    @Test("evaluateProvenanceQuality returns 0 for unknown state")
    func evaluateQualityUnknown() throws {
        let mockEvaluate: ProvenanceBridge.EvaluateQualityFn = { _, _, _, _ in
            0
        }

        let tier = try evaluateProvenanceQuality(
            sourceType: "persistent",
            contextState: "unknown",
            evaluateQualityFn: mockEvaluate
        )

        #expect(tier == 0)
    }

    @Test("evaluateProvenanceQuality propagates bridge errors")
    func evaluateQualityError() throws {
        let mockEvaluate: ProvenanceBridge.EvaluateQualityFn = { _, _, _, _ in
            throw ScpError.Validation(
                msg: "invalid source type",
                code: "SCP-VALID-7201"
            )
        }

        do {
            _ = try evaluateProvenanceQuality(
                sourceType: "invalid",
                contextState: "active",
                evaluateQualityFn: mockEvaluate
            )
            Issue.record("Expected evaluateProvenanceQuality to throw")
        } catch {
            #expect(error is ScpError)
        }
    }

    // MARK: - attachProvenance via injectable bridge (roundtrip)

    @Test("attachProvenance calls bridge and returns JSON")
    func attachProvenanceRoundtrip() throws {
        var receivedSourceContextId: String?
        var receivedTargetContextId: String?

        let mockAttach: ProvenanceBridge.AttachFn = { sourceContextId, _, _, _, targetContextId, _, _ in
            receivedSourceContextId = sourceContextId
            receivedTargetContextId = targetContextId
            return #"{"source_context":"\#(sourceContextId)","target_context":"\#(targetContextId)","chain_depth":0}"#
        }

        let result = try attachProvenance(
            sourceContextId: "ctx-source",
            sourceType: "persistent",
            memoryScope: "full",
            members: ["did:dht:z6MkAlice"],
            targetContextId: "ctx-target",
            actorDid: "did:dht:z6MkActor",
            attachFn: mockAttach
        )

        #expect(receivedSourceContextId == "ctx-source")
        #expect(receivedTargetContextId == "ctx-target")
        #expect(result.contains("ctx-source"))
        #expect(result.contains("ctx-target"))
    }

    // MARK: - checkProvenanceChainDepth via injectable bridge (roundtrip)

    @Test("checkProvenanceChainDepth calls bridge with correct parameters")
    func checkChainDepthRoundtrip() {
        var receivedChainDepth: UInt8?
        var receivedMaxDepth: UInt8?

        let mockCheck: ProvenanceBridge.CheckChainDepthFn = { chainDepth, maxDepth in
            receivedChainDepth = chainDepth
            receivedMaxDepth = maxDepth
            return chainDepth <= (maxDepth ?? 8)
        }

        let withinLimit = checkProvenanceChainDepth(
            chainDepth: 2,
            maxDepth: 5,
            checkChainDepthFn: mockCheck
        )

        #expect(withinLimit)
        #expect(receivedChainDepth == 2)
        #expect(receivedMaxDepth == 5)
    }

    @Test("checkProvenanceChainDepth returns false when exceeded")
    func checkChainDepthExceeded() {
        let mockCheck: ProvenanceBridge.CheckChainDepthFn = { chainDepth, maxDepth in
            chainDepth <= (maxDepth ?? 8)
        }

        let withinLimit = checkProvenanceChainDepth(
            chainDepth: 9,
            checkChainDepthFn: mockCheck
        )

        #expect(!withinLimit)
    }
} // end ProvenanceTests
