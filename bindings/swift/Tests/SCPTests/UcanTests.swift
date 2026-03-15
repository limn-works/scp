import Foundation
@testable import SCP
import Testing

// MARK: - UCAN Tests

/// Tests for UCAN token operations: validate, mint, revoke, and delegation.
///
/// UniFFI generates UcanToken as an open class with methods:
///   - issuer() -> String
///   - audience() -> String
///   - expiresAt() -> UInt64?
///   - tokenId() -> String
///   - capabilities() -> [String]
///   - tokenData() -> UcanTokenData
///
/// Tests that need mock UcanToken instances use subclasses with `noPointer:`.
/// Async roundtrip tests inject mock bridge functions to verify the delegation
/// pattern works end-to-end without a real UniFFI binary.
///
/// See ADR-016 (UCAN), ADR-026 (Swift SDK), and story SCP-221.
struct UcanTests {
    // MARK: - Mock UcanToken subclass

    /// Mock subclass of the UniFFI-generated `UcanToken` class for testing.
    private final class MockUcanToken: UcanToken, @unchecked Sendable {
        let mockIssuer: String
        let mockAudience: String
        let mockExpiry: UInt64?
        let mockTokenId: String
        let mockCapabilities: [String]

        init(
            issuer: String,
            audience: String,
            expiry: UInt64?,
            tokenId: String = "token-\(UUID().uuidString)",
            capabilities: [String] = []
        ) {
            mockIssuer = issuer
            mockAudience = audience
            mockExpiry = expiry
            mockTokenId = tokenId
            mockCapabilities = capabilities
            super.init(noPointer: .init())
        }

        required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
            mockIssuer = ""
            mockAudience = ""
            mockExpiry = nil
            mockTokenId = ""
            mockCapabilities = []
            super.init(unsafeFromRawPointer: pointer)
        }

        override func issuer() -> String {
            mockIssuer
        }

        override func audience() -> String {
            mockAudience
        }

        override func expiresAt() -> UInt64? {
            mockExpiry
        }

        override func tokenId() -> String {
            mockTokenId
        }

        override func capabilities() -> [String] {
            mockCapabilities
        }
    }

    // MARK: - UcanToken type shape

    @Test("UcanToken mock stores all fields correctly")
    func ucanTokenFields() {
        let token = MockUcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400,
            tokenId: "token-abc-123",
            capabilities: ["scp:ctx:abc/messages:write"]
        )

        #expect(token.issuer() == "did:dht:z6MkIssuer")
        #expect(token.audience() == "did:dht:z6MkAudience")
        #expect(token.expiresAt() == 1_700_086_400)
        #expect(token.tokenId() == "token-abc-123")
        #expect(token.capabilities().count == 1)
    }

    @Test("UcanToken with nil expiry")
    func ucanTokenNilExpiry() {
        let token = MockUcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: nil
        )
        #expect(token.expiresAt() == nil)
    }

    @Test("UcanToken is Sendable")
    func ucanTokenIsSendable() {
        let token: any Sendable = MockUcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400
        )
        #expect(token is UcanToken)
    }

    // MARK: - UcanCapability type shape

    @Test("UcanCapability stores resource and action")
    func ucanCapabilityFields() {
        let cap = UcanCapability(
            resource: "scp:ctx:my-context/messages:write",
            action: "invoke"
        )
        #expect(cap.resource == "scp:ctx:my-context/messages:write")
        #expect(cap.action == "invoke")
    }

    @Test("UcanCapability with wildcard resource")
    func ucanCapabilityWildcard() {
        let cap = UcanCapability(
            resource: "scp:ctx:*/messages:write",
            action: "invoke"
        )
        #expect(cap.resource.contains("*"))
    }

    @Test("UcanCapability is Sendable")
    func ucanCapabilityIsSendable() {
        let cap: any Sendable = UcanCapability(resource: "scp:ctx:x", action: "read")
        #expect(cap is UcanCapability)
    }

    // MARK: - UcanValidationResult type shape

    @Test("UcanValidationResult valid result stores token")
    func validationResultValid() {
        let token = MockUcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400
        )
        let result = UcanValidationResult(
            isValid: true,
            token: token,
            failureReason: nil
        )
        #expect(result.isValid)
        #expect(result.token != nil)
        #expect(result.failureReason == nil)
    }

    @Test("UcanValidationResult invalid result stores reason")
    func validationResultInvalid() {
        let result = UcanValidationResult(
            isValid: false,
            token: nil,
            failureReason: "Token expired"
        )
        #expect(!result.isValid)
        #expect(result.token == nil)
        #expect(result.failureReason == "Token expired")
    }

    // MARK: - Validate via injectable bridge (async roundtrip)

    @Test("validateUcanToken calls bridge successfully")
    func validateRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        nonisolated(unsafe) var receivedToken: String?
        nonisolated(unsafe) var receivedCapability: String?
        let mockValidate: UcanBridge.ValidateFn = { _, token, capability, _, _ in
            receivedToken = token
            receivedCapability = capability
        }
        try await validateUcanToken(
            handle: handle,
            token: "eyJhbGciOiJFZERTQSJ9.test.sig",
            capability: "messages:write",
            validateFn: mockValidate
        )
        #expect(receivedToken == "eyJhbGciOiJFZERTQSJ9.test.sig")
        #expect(receivedCapability == "messages:write")
    }

    // MARK: - Mint via injectable bridge (async roundtrip)

    @Test("mintUcanToken calls bridge and returns token")
    func mintRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let mockToken = MockUcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400,
            tokenId: "minted-token-001",
            capabilities: ["scp:ctx:abc/messages:write"]
        )

        let mockMint: UcanBridge.MintFn = { _, memberDid, capabilities in
            #expect(memberDid == "did:dht:z6MkMember")
            #expect(capabilities.count == 1)
            return mockToken
        }

        let result = try await mintUcanToken(
            handle: handle,
            memberDid: "did:dht:z6MkMember",
            capabilities: ["scp:ctx:abc/messages:write"],
            mintFn: mockMint
        )

        #expect(result.tokenId() == "minted-token-001")
        #expect(result.issuer() == "did:dht:z6MkIssuer")
    }

    // MARK: - Revoke via injectable bridge (async roundtrip)

    @Test("revokeUcanToken calls bridge successfully")
    func revokeRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        nonisolated(unsafe) var revokedToken: String?
        let mockRevoke: UcanBridge.RevokeFn = { _, token, _ in revokedToken = token }
        try await revokeUcanToken(
            handle: handle, token: "header.payload.signature", revokerDid: "did:dht:z6MkRevoker", revokeFn: mockRevoke
        )
        #expect(revokedToken == "header.payload.signature")
    }

    // MARK: - Legacy API

    @Test("legacy validate passes capability and presenterDid in correct arg positions")
    func legacyValidateArgOrder() async throws {
        let handle = ContextHandle(noPointer: .init())
        nonisolated(unsafe) var capArg = ""
        nonisolated(unsafe) var didArg: String?
        let mock: UcanBridge.ValidateFn = { _, _, cap, did, _ in capArg = cap; didArg = did }
        let res = try await validate(
            encoded: "tok", handle: handle, contextId: "ctx",
            capability: "messages:write", presenterDid: "did:dht:z6MkP", validateFn: mock
        )
        #expect(res.isValid && capArg == "messages:write" && didArg == "did:dht:z6MkP")
        let res2 = try await validate(
            encoded: "tok", handle: handle, contextId: "ctx",
            capability: "messages:read", validateFn: mock
        )
        #expect(res2.isValid && capArg == "messages:read" && didArg == nil)
    }

    @Test("legacy mint delegates to bridge")
    func legacyMintRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let mockToken = MockUcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: nil,
            tokenId: "legacy-mint-token"
        )
        let mockMint: UcanBridge.MintFn = { _, _, _ in mockToken }

        let result = try await mint(
            handle: handle,
            issuerDid: "did:dht:z6MkIssuer",
            audienceDid: "did:dht:z6MkAudience",
            capabilities: [UcanCapability(resource: "scp:ctx:test", action: "write")],
            mintFn: mockMint
        )

        #expect(result.tokenId() == "legacy-mint-token")
    }

    @Test("legacy revoke delegates to bridge")
    func legacyRevokeRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        nonisolated(unsafe) var revoked = false
        let mockRevoke: UcanBridge.RevokeFn = { _, _, _ in revoked = true }

        try await revoke(
            handle: handle,
            encoded: "eyJhbGciOiJFZERTQSJ9.test.sig",
            revokerDid: "did:dht:z6MkRevoker",
            revokeFn: mockRevoke
        )

        #expect(revoked)
    }

    // MARK: - Delegate via injectable bridge (async roundtrip)

    @Test("delegateUcanToken calls bridge and returns delegated token")
    func delegateRoundtrip() async throws {
        let handle = ContextHandle(noPointer: .init())
        let mockToken = MockUcanToken(
            issuer: "did:dht:z6MkDelegator",
            audience: "did:dht:z6MkDelegatee",
            expiry: 1_700_090_000,
            tokenId: "delegated-token-001",
            capabilities: ["scp:ctx:abc/messages:read"]
        )

        nonisolated(unsafe) var receivedDelegatorDid: String?
        nonisolated(unsafe) var receivedDelegateeDid: String?
        nonisolated(unsafe) var receivedParentToken: String?
        nonisolated(unsafe) var receivedCapabilities: [String]?

        let mockDelegate: UcanBridge.DelegateFn = { _, delegatorDid, delegateeDid, parentToken, capabilities in
            receivedDelegatorDid = delegatorDid
            receivedDelegateeDid = delegateeDid
            receivedParentToken = parentToken
            receivedCapabilities = capabilities
            return mockToken
        }

        let result = try await delegateUcanToken(
            handle: handle,
            delegatorDid: "did:dht:z6MkDelegator",
            delegateeDid: "did:dht:z6MkDelegatee",
            parentToken: "eyJhbGciOiJFZERTQSJ9.parent.sig",
            capabilities: ["scp:ctx:abc/messages:read"],
            delegateFn: mockDelegate
        )

        #expect(result.tokenId() == "delegated-token-001")
        #expect(result.issuer() == "did:dht:z6MkDelegator")
        #expect(result.audience() == "did:dht:z6MkDelegatee")
        #expect(receivedDelegatorDid == "did:dht:z6MkDelegator")
        #expect(receivedDelegateeDid == "did:dht:z6MkDelegatee")
        #expect(receivedParentToken == "eyJhbGciOiJFZERTQSJ9.parent.sig")
        #expect(receivedCapabilities == ["scp:ctx:abc/messages:read"])
    }

    @Test("delegateUcanToken propagates bridge errors")
    func delegatePropagatesErrors() async throws {
        let handle = ContextHandle(noPointer: .init())

        let mockDelegate: UcanBridge.DelegateFn = { _, _, _, _, _ in
            throw ScpError.Permission(
                msg: "capabilities wider than parent",
                code: "SCP-PERM-3004"
            )
        }

        do {
            _ = try await delegateUcanToken(
                handle: handle,
                delegatorDid: "did:dht:z6MkDelegator",
                delegateeDid: "did:dht:z6MkDelegatee",
                parentToken: "eyJhbGciOiJFZERTQSJ9.parent.sig",
                capabilities: ["scp:ctx:*/admin:*"],
                delegateFn: mockDelegate
            )
            Issue.record("Expected delegateUcanToken to throw")
        } catch let error as ScpError {
            if case let .Permission(_, code) = error {
                #expect(code == "SCP-PERM-3004")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("delegateUcanToken default delegates to UniFFI")
    func delegateDefaultDelegatesToUniFFI() {
        // The default delegate function now delegates to the UniFFI-generated
        // ``ucanDelegate(handle:delegatorDid:delegateeDid:parentToken:capabilities:)``
        // binding. Verifying the default is non-throwing requires the
        // XCFramework; this test confirms the typealias and default are
        // properly wired by verifying the injectable bridge pattern still
        // works with mocks.
        // Verify the default delegate static property is accessible and correctly typed.
        // Assigning to a typed binding confirms the typealias wiring at compile time.
        let _: UcanBridge.DelegateFn = UcanBridge.defaultDelegate
    }
} // end UcanTests
