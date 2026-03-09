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

        let mockEvaluate: BridgeConnectorBridge.EvaluateTrustFn = { isBridged, isNativeTransport, shadowStatus in
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

    // MARK: - bridgeRegister via injectable bridge (roundtrip)

    @Test("bridgeRegister calls bridge and returns registration result")
    func bridgeRegisterRoundtrip() throws {
        var receivedContextId: String?
        var receivedOperatorDid: String?
        var receivedPlatform: String?
        var receivedMode: String?

        let mockRegister: BridgeConnectorBridge.RegisterFn = { contextId, operatorDid, platform, mode in
            receivedContextId = contextId
            receivedOperatorDid = operatorDid
            receivedPlatform = platform
            receivedMode = mode
            return BridgeRegistrationResult(
                bridgeId: "bridge-new",
                operatorDid: operatorDid,
                platform: platform,
                mode: mode,
                status: "active",
                contextId: contextId
            )
        }

        let result = try bridgeRegister(
            contextId: "ctx-001",
            operatorDid: "did:dht:z6MkOp",
            platform: "discord",
            mode: "relay",
            registerFn: mockRegister
        )

        #expect(receivedContextId == "ctx-001")
        #expect(receivedOperatorDid == "did:dht:z6MkOp")
        #expect(receivedPlatform == "discord")
        #expect(receivedMode == "relay")
        #expect(result.bridgeId == "bridge-new")
        #expect(result.status == "active")
    }

    @Test("bridgeRegister default throws descriptive error")
    func bridgeRegisterDefaultThrows() {
        do {
            _ = try bridgeRegister(
                contextId: "ctx-001",
                operatorDid: "did:dht:z6MkOp",
                platform: "discord",
                mode: "relay"
            )
            Issue.record("Expected bridgeRegister to throw")
        } catch {
            #expect(error is ScpError)
        }
    }

    // MARK: - bridgeCreateShadow via injectable bridge (roundtrip)

    @Test("bridgeCreateShadow calls bridge and returns shadow result")
    func bridgeCreateShadowRoundtrip() throws {
        var receivedBridgeId: String?
        var receivedHandle: String?
        var receivedMode: String?
        var receivedContextId: String?

        let mockCreateShadow: BridgeConnectorBridge.CreateShadowFn = { bridgeId, handle, mode, contextId in
            receivedBridgeId = bridgeId
            receivedHandle = handle
            receivedMode = mode
            receivedContextId = contextId
            return ShadowIdentityResult(
                shadowId: "shadow-new",
                platformHandle: handle,
                bridgeId: bridgeId,
                attributedRole: "member",
                provenanceStatus: "Shadow"
            )
        }

        let result = try bridgeCreateShadow(
            bridgeId: "bridge-001",
            platformHandle: "@alice#1234",
            bridgeMode: "relay",
            contextId: "ctx-bridge-001",
            createShadowFn: mockCreateShadow
        )

        #expect(receivedBridgeId == "bridge-001")
        #expect(receivedHandle == "@alice#1234")
        #expect(receivedMode == "relay")
        #expect(receivedContextId == "ctx-bridge-001")
        #expect(result.shadowId == "shadow-new")
        #expect(result.provenanceStatus == "Shadow")
    }

    @Test("bridgeCreateShadow default throws descriptive error")
    func bridgeCreateShadowDefaultThrows() {
        do {
            _ = try bridgeCreateShadow(
                bridgeId: "bridge-001",
                platformHandle: "@alice",
                bridgeMode: "relay",
                contextId: "ctx-001"
            )
            Issue.record("Expected bridgeCreateShadow to throw")
        } catch {
            #expect(error is ScpError)
        }
    }
} // end BridgeTests
