import Foundation
@testable import SCP
import Testing

// MARK: - Bridge Tests

/// Tests for bridge connector operations: trust evaluation via injectable
/// bridge closures.
///
/// See spec section 12 (Bridge System) and ADR-023 (Bridge Connector).
struct BridgeTests {
    // MARK: - BridgeRegistrationResult type shape

    @Test("BridgeRegistrationResult stores all fields")
    func bridgeRegistrationResultFields() {
        let result = BridgeRegistrationResult(
            bridgeId: "bridge-001",
            operatorDid: "did:dht:z6MkOperator",
            platform: "discord",
            mode: "relay",
            status: "active",
            contextId: "ctx-bridge-001"
        )

        #expect(result.bridgeId == "bridge-001")
        #expect(result.operatorDid == "did:dht:z6MkOperator")
        #expect(result.platform == "discord")
        #expect(result.mode == "relay")
        #expect(result.status == "active")
        #expect(result.contextId == "ctx-bridge-001")
    }

    @Test("BridgeRegistrationResult is Sendable")
    func bridgeRegistrationResultIsSendable() {
        let result: any Sendable = BridgeRegistrationResult(
            bridgeId: "bridge-001",
            operatorDid: "did:dht:z6MkOp",
            platform: "slack",
            mode: "api",
            status: "active",
            contextId: "ctx-001"
        )
        #expect(result is BridgeRegistrationResult)
    }

    // MARK: - ShadowIdentityResult type shape

    @Test("ShadowIdentityResult stores all fields")
    func shadowIdentityResultFields() {
        let result = ShadowIdentityResult(
            shadowId: "shadow-001",
            platformHandle: "@alice",
            bridgeId: "bridge-001",
            attributedRole: "member",
            provenanceStatus: "Shadow"
        )

        #expect(result.shadowId == "shadow-001")
        #expect(result.platformHandle == "@alice")
        #expect(result.bridgeId == "bridge-001")
        #expect(result.attributedRole == "member")
        #expect(result.provenanceStatus == "Shadow")
    }

    // MARK: - evaluateBridgeTrust via injectable bridge (roundtrip)

    @Test("evaluateBridgeTrust calls bridge and returns trust tier")
    func evaluateBridgeTrustRoundtrip() throws {
        var receivedIsBridged: Bool?
        var receivedIsNativeTransport: Bool?
        var receivedShadowStatus: String?

        let mockEvaluate: BridgeConnectorBridge.EvaluateTrustFn = {
            isBridged, isNativeTransport, shadowStatus in
            receivedIsBridged = isBridged
            receivedIsNativeTransport = isNativeTransport
            receivedShadowStatus = shadowStatus
            return 2
        }

        let tier = try evaluateBridgeTrust(
            isBridged: true,
            isNativeTransport: false,
            shadowStatus: "claimed",
            evaluateTrustFn: mockEvaluate
        )

        #expect(tier == 2)
        #expect(receivedIsBridged == true)
        #expect(receivedIsNativeTransport == false)
        #expect(receivedShadowStatus == "claimed")
    }

    @Test("evaluateBridgeTrust returns 0 for native-native")
    func evaluateBridgeTrustNativeNative() throws {
        let mockEvaluate: BridgeConnectorBridge.EvaluateTrustFn = { _, _, _ in
            0
        }

        let tier = try evaluateBridgeTrust(
            isBridged: false,
            isNativeTransport: true,
            shadowStatus: "none",
            evaluateTrustFn: mockEvaluate
        )

        #expect(tier == 0)
    }

    @Test("evaluateBridgeTrust returns 3 for shadow-bridged")
    func evaluateBridgeTrustShadowBridged() throws {
        let mockEvaluate: BridgeConnectorBridge.EvaluateTrustFn = { _, _, _ in
            3
        }

        let tier = try evaluateBridgeTrust(
            isBridged: true,
            isNativeTransport: false,
            shadowStatus: "shadow",
            evaluateTrustFn: mockEvaluate
        )

        #expect(tier == 3)
    }
} // end BridgeTests
