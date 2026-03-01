import Foundation
import Testing

@testable import SCP

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
/// Tests that exercise bridge stubs verify error propagation through
/// CheckedContinuation.
///
/// See ADR-016 (UCAN), ADR-026 (Swift SDK), and story SCP-102.
@Suite("UCAN Tests")
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
            self.mockIssuer = issuer
            self.mockAudience = audience
            self.mockExpiry = expiry
            self.mockTokenId = tokenId
            self.mockCapabilities = capabilities
            super.init(noPointer: .init())
        }

        required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
            self.mockIssuer = ""
            self.mockAudience = ""
            self.mockExpiry = nil
            self.mockTokenId = ""
            self.mockCapabilities = []
            super.init(unsafeFromRawPointer: pointer)
        }

        override func issuer() -> String { mockIssuer }
        override func audience() -> String { mockAudience }
        override func expiresAt() -> UInt64? { mockExpiry }
        override func tokenId() -> String { mockTokenId }
        override func capabilities() -> [String] { mockCapabilities }
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
    func ucanTokenIsSendable() async {
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
    func ucanCapabilityIsSendable() async {
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

    // MARK: - Validate (bridge stub error propagation)

    @Test("validate throws bridge error with SCP-PERM-3001")
    func validateThrowsBridgeError() async {
        do {
            _ = try await validate(
                encoded: "eyJhbGciOiJFZERTQSJ9.test.sig",
                contextId: "ctx-001",
                presenterDid: "did:dht:z6MkPresenter"
            )
            Issue.record("Expected validate to throw")
        } catch let error as ScpError {
            if case .Permission(_, let code) = error {
                #expect(code == "SCP-PERM-3001")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Mint (bridge stub error propagation)

    @Test("mint throws bridge error with SCP-PERM-3002")
    func mintThrowsBridgeError() async {
        do {
            _ = try await mint(
                issuerDid: "did:dht:z6MkIssuer",
                audienceDid: "did:dht:z6MkAudience",
                capabilities: [
                    UcanCapability(resource: "scp:ctx:test/messages:write", action: "invoke"),
                ],
                expirySecs: 3_600,
                proofs: []
            )
            Issue.record("Expected mint to throw")
        } catch let error as ScpError {
            if case .Permission(_, let code) = error {
                #expect(code == "SCP-PERM-3002")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("mint with default expiry and empty proofs")
    func mintWithDefaults() async {
        // Verify the default parameter values are accepted by the function signature.
        do {
            _ = try await mint(
                issuerDid: "did:dht:z6MkIssuer",
                audienceDid: "did:dht:z6MkAudience",
                capabilities: []
            )
            Issue.record("Expected mint to throw")
        } catch let error as ScpError {
            // The bridge stub error is expected -- we're verifying default params work.
            if case .Permission(_, let code) = error {
                #expect(code == "SCP-PERM-3002")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Revoke (bridge stub error propagation)

    @Test("revoke throws bridge error with SCP-PERM-3003")
    func revokeThrowsBridgeError() async {
        do {
            try await revoke(
                encoded: "eyJhbGciOiJFZERTQSJ9.test.sig",
                revokerDid: "did:dht:z6MkRevoker"
            )
            Issue.record("Expected revoke to throw")
        } catch let error as ScpError {
            if case .Permission(_, let code) = error {
                #expect(code == "SCP-PERM-3003")
            } else {
                Issue.record("Expected ScpError.Permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

} // end UcanTests
