import Foundation
import Testing

@testable import SCP

// MARK: - UCAN Tests

/// Tests for UCAN token operations: validate, mint, revoke, and delegation.
///
/// These tests validate the Swift ergonomics layer and type shapes for UCAN
/// authorization. The UniFFI bridge stubs return placeholder errors until
/// SCP-103 ships.
///
/// See ADR-016 (UCAN), ADR-026 (Swift SDK), and story SCP-102.
@Suite("UCAN Tests")
struct UcanTests {

    // MARK: - UcanToken type shape

    @Test("UcanToken stores all fields correctly")
    func ucanTokenFields() {
        let capabilities = [
            UcanCapability(resource: "scp:ctx:abc/messages:write", action: "invoke"),
        ]
        let token = UcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400,
            notBefore: 1_700_000_000,
            nonce: "nonce-abc-123",
            capabilities: capabilities,
            proofs: ["parent-token-encoded"],
            encoded: "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.payload.sig"
        )

        #expect(token.issuer == "did:dht:z6MkIssuer")
        #expect(token.audience == "did:dht:z6MkAudience")
        #expect(token.expiry == 1_700_086_400)
        #expect(token.notBefore == 1_700_000_000)
        #expect(token.nonce == "nonce-abc-123")
        #expect(token.capabilities.count == 1)
        #expect(token.proofs.count == 1)
        #expect(token.encoded.contains("eyJ"))
    }

    @Test("UcanToken with nil notBefore")
    func ucanTokenNilNotBefore() {
        let token = UcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400,
            notBefore: nil,
            nonce: "nonce-001",
            capabilities: [],
            proofs: [],
            encoded: "encoded-token"
        )
        #expect(token.notBefore == nil)
    }

    @Test("UcanToken is Sendable")
    func ucanTokenIsSendable() async {
        let token: any Sendable = UcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400,
            notBefore: nil,
            nonce: "nonce-001",
            capabilities: [],
            proofs: [],
            encoded: "encoded"
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
        let token = UcanToken(
            issuer: "did:dht:z6MkIssuer",
            audience: "did:dht:z6MkAudience",
            expiry: 1_700_086_400,
            notBefore: nil,
            nonce: "nonce-001",
            capabilities: [],
            proofs: [],
            encoded: "encoded"
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

    @Test("validate throws bridge error with SCP-UCAN-001")
    func validateThrowsBridgeError() async {
        do {
            _ = try await validate(
                encoded: "eyJhbGciOiJFZERTQSJ9.test.sig",
                contextId: "ctx-001",
                presenterDid: "did:dht:z6MkPresenter"
            )
            Issue.record("Expected validate to throw")
        } catch let error as ScpError {
            if case .permission(_, let code) = error {
                #expect(code == "SCP-UCAN-001")
            } else {
                Issue.record("Expected ScpError.permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Mint (bridge stub error propagation)

    @Test("mint throws bridge error with SCP-UCAN-002")
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
            if case .permission(_, let code) = error {
                #expect(code == "SCP-UCAN-002")
            } else {
                Issue.record("Expected ScpError.permission, got \(error)")
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
            // The bridge stub error is expected — we're verifying default params work.
            if case .permission(_, let code) = error {
                #expect(code == "SCP-UCAN-002")
            } else {
                Issue.record("Expected ScpError.permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Revoke (bridge stub error propagation)

    @Test("revoke throws bridge error with SCP-UCAN-003")
    func revokeThrowsBridgeError() async {
        do {
            try await revoke(
                encoded: "eyJhbGciOiJFZERTQSJ9.test.sig",
                revokerDid: "did:dht:z6MkRevoker"
            )
            Issue.record("Expected revoke to throw")
        } catch let error as ScpError {
            if case .permission(_, let code) = error {
                #expect(code == "SCP-UCAN-003")
            } else {
                Issue.record("Expected ScpError.permission, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Delegation chain

    @Test("UcanToken delegation chain carries parent proofs")
    func delegationChainCarriesProofs() {
        // Simulate a delegation chain: root -> delegate1 -> delegate2
        let rootToken = UcanToken(
            issuer: "did:dht:z6MkRoot",
            audience: "did:dht:z6MkDelegate1",
            expiry: 1_700_086_400,
            notBefore: nil,
            nonce: "nonce-root",
            capabilities: [
                UcanCapability(resource: "scp:ctx:test/messages:write", action: "invoke"),
            ],
            proofs: [],
            encoded: "root-encoded"
        )

        let delegatedToken = UcanToken(
            issuer: "did:dht:z6MkDelegate1",
            audience: "did:dht:z6MkDelegate2",
            expiry: 1_700_086_400,
            notBefore: nil,
            nonce: "nonce-delegated",
            capabilities: [
                UcanCapability(resource: "scp:ctx:test/messages:write", action: "invoke"),
            ],
            proofs: [rootToken.encoded],
            encoded: "delegated-encoded"
        )

        #expect(rootToken.proofs.isEmpty)
        #expect(delegatedToken.proofs.count == 1)
        #expect(delegatedToken.proofs[0] == rootToken.encoded)
        // Delegation can only attenuate (narrow) capabilities
        #expect(delegatedToken.capabilities.count <= rootToken.capabilities.count)
    }

} // end UcanTests
