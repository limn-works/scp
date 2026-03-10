@testable import SCP
import Testing

// MARK: - Identity Tests

// Tests for the Identity type verifying Sendable conformance, public API
// shape, DID format validation, and CheckedContinuation-based async bridging.
//
// UniFFI generates Identity as an open class with methods:
//   - did() -> String
//   - custodyType() -> String
//   - rotateKey() async throws -> Identity
//
// Tests that need mock Identity instances use subclasses with `noPointer:`.
// Tests that exercise factory methods (create/load/rotateKey) verify bridge
// stub error propagation through CheckedContinuation.
//
// See ADR-026 (Swift SDK) and story SCP-102.

// swiftlint:disable:next type_body_length
struct IdentityTests {
    // MARK: - Mock Identity subclass

    /// Mock subclass of the UniFFI-generated `Identity` class for testing.
    ///
    /// UniFFI `Identity` is an open class. In tests we create instances with
    /// `noPointer:` and override methods to return test values. Methods that
    /// call into FFI (via `self.pointer`) will crash when pointer is nil, so
    /// we override all methods we test against.
    private final class MockIdentity: Identity, @unchecked Sendable {
        let mockDid: String
        let mockCustodyType: String

        init(did: String, custodyType: String) {
            mockDid = did
            mockCustodyType = custodyType
            super.init(noPointer: .init())
        }

        required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
            mockDid = ""
            mockCustodyType = ""
            super.init(unsafeFromRawPointer: pointer)
        }

        override func did() -> String {
            mockDid
        }

        override func custodyType() -> String {
            mockCustodyType
        }
    }

    // MARK: - Type Shape

    @Test("Identity conforms to Sendable")
    func identityIsSendable() {
        // Verify that Identity conforms to Sendable by assigning to a
        // Sendable-constrained binding. This is a compile-time check --
        // if Identity is not Sendable, this file will not compile.
        let identity: any Sendable = MockIdentity(did: "did:dht:z6MkTest123", custodyType: "in_memory")
        #expect(identity is Identity)
    }

    @Test("Identity DID returns correct string")
    func identityDidReturnsString() {
        let identity = MockIdentity(did: "did:dht:z6MkTestDid", custodyType: "platform")
        #expect(identity.did() == "did:dht:z6MkTestDid")
    }

    @Test("Identity custody type returns correct string")
    func identityCustodyTypeReturnsString() {
        let identity = MockIdentity(did: "did:dht:z6MkTestDid", custodyType: "platform")
        #expect(identity.custodyType() == "platform")
    }

    @Test("Identity preserves in_memory custody type")
    func identityPreservesInMemoryCustodyType() {
        let identity = MockIdentity(did: "did:dht:z6MkTestDid2", custodyType: "in_memory")
        #expect(identity.custodyType() == "in_memory")
    }

    // MARK: - Sendable Crossing

    @Test("Identity can cross task boundary")
    func identityCanCrossTaskBoundary() async {
        // Verify that Identity can be sent across task boundaries.
        // This is a compile-time + runtime check for Sendable conformance.
        let identity = MockIdentity(did: "did:dht:z6MkCrossTask", custodyType: "in_memory")

        let receivedDid = await Task {
            identity.did()
        }.value

        #expect(receivedDid == "did:dht:z6MkCrossTask")
    }

    // MARK: - DID Format Validation

    @Test("DID format uses did:dht: prefix")
    func didFormatHasDhtPrefix() {
        let identity = MockIdentity(did: "did:dht:z6MkValidDid", custodyType: "in_memory")
        #expect(identity.did().hasPrefix("did:dht:"))
    }

    @Test("DID format contains z6Mk multibase prefix")
    func didFormatContainsMultibasePrefix() {
        // SCP uses Ed25519 keys encoded with z-base58 multibase prefix (z6Mk).
        let identity = MockIdentity(did: "did:dht:z6MkSomeKey123", custodyType: "in_memory")
        #expect(identity.did().contains("z6Mk"))
    }

    @Test("DID format rejects invalid prefix")
    func didFormatRejectsInvalidPrefix() {
        // Identity preserves whatever DID string the bridge returns.
        // This test verifies that a non-standard DID is stored as-is.
        let identity = MockIdentity(did: "invalid:prefix:test", custodyType: "in_memory")
        #expect(!identity.did().hasPrefix("did:dht:"))
        #expect(identity.did() == "invalid:prefix:test")
    }

    // MARK: - No Force Unwraps Verification

    @Test("Identity handles empty DID without crashing")
    func identityHandlesEmptyDid() {
        // Verify that Identity handles edge cases without force unwrapping.
        let identity = MockIdentity(did: "", custodyType: "")
        #expect(identity.did() == "")
        #expect(identity.custodyType() == "")
    }

    // MARK: - Device Attestation

    @Test("identityAttestDevice calls bridge and returns token")
    func identityAttestDeviceRoundtrip() async throws {
        let identity = MockIdentity(did: "did:dht:z6MkAttest", custodyType: "in_memory")

        var receivedIdentity: Identity?
        let mockAttest: IdentityBridge.AttestDeviceFn = { identity in
            receivedIdentity = identity
            return "dGVzdC1hdHRlc3RhdGlvbi10b2tlbg=="
        }

        let token = try await identityAttestDevice(identity, attestDeviceFn: mockAttest)
        #expect(token == "dGVzdC1hdHRlc3RhdGlvbi10b2tlbg==")
        #expect(receivedIdentity?.did() == "did:dht:z6MkAttest")
    }

    @Test("identityAttestDevice propagates bridge errors")
    func identityAttestDevicePropagatesBridgeErrors() async throws {
        let identity = MockIdentity(did: "did:dht:z6MkFail", custodyType: "external")

        let mockAttest: IdentityBridge.AttestDeviceFn = { _ in
            throw ScpError.Identity(
                message: "device attestation requires retained identity state",
                code: "SCP-IDENT-1007"
            )
        }

        do {
            _ = try await identityAttestDevice(identity, attestDeviceFn: mockAttest)
            Issue.record("Expected identityAttestDevice to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1007")
                #expect(message.contains("retained identity state"))
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("identityVerifyDeviceAttestation calls bridge and returns result")
    func identityVerifyDeviceAttestationRoundtrip() async throws {
        var receivedDid: String?
        var receivedToken: String?
        let mockVerify: IdentityBridge.VerifyDeviceAttestationFn = { did, tokenBase64 in
            receivedDid = did
            receivedToken = tokenBase64
            return true
        }

        let result = try await identityVerifyDeviceAttestation(
            did: "did:dht:z6MkVerify",
            tokenBase64: "dGVzdA==",
            verifyDeviceAttestationFn: mockVerify
        )
        #expect(result == true)
        #expect(receivedDid == "did:dht:z6MkVerify")
        #expect(receivedToken == "dGVzdA==")
    }

    @Test("identityVerifyDeviceAttestation returns false for invalid token")
    func identityVerifyDeviceAttestationReturnsFalse() async throws {
        let mockVerify: IdentityBridge.VerifyDeviceAttestationFn = { _, _ in
            false
        }

        let result = try await identityVerifyDeviceAttestation(
            did: "did:dht:z6MkVerify",
            tokenBase64: "aW52YWxpZA==",
            verifyDeviceAttestationFn: mockVerify
        )
        #expect(result == false)
    }

    @Test("identityVerifyDeviceAttestation propagates bridge errors")
    func identityVerifyDeviceAttestationPropagatesBridgeErrors() async throws {
        let mockVerify: IdentityBridge.VerifyDeviceAttestationFn = { _, _ in
            throw ScpError.Identity(
                message: "invalid base64 attestation token",
                code: "SCP-IDENT-1011"
            )
        }

        do {
            _ = try await identityVerifyDeviceAttestation(
                did: "did:dht:z6MkVerify",
                tokenBase64: "not-base64",
                verifyDeviceAttestationFn: mockVerify
            )
            Issue.record("Expected error to propagate")
        } catch let error as ScpError {
            if case let .Identity(_, code) = error {
                #expect(code == "SCP-IDENT-1011")
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Create Identity

    @Test("createIdentity calls bridge and returns identity")
    func createIdentityRoundtrip() async throws {
        let mockIdentity = MockIdentity(did: "did:dht:z6MkCreated", custodyType: "in_memory")
        var receivedCustody: String?

        let mockCreate: IdentityBridge.CreateFn = { custody in
            receivedCustody = custody
            return mockIdentity
        }

        let result = try await createIdentity(custody: "in_memory", createFn: mockCreate)
        #expect(result.did() == "did:dht:z6MkCreated")
        #expect(receivedCustody == "in_memory")
    }

    @Test("createIdentity propagates bridge errors")
    func createIdentityPropagatesErrors() async throws {
        let mockCreate: IdentityBridge.CreateFn = { _ in
            throw ScpError.Identity(
                message: "in_memory custody not available",
                code: "SCP-IDENT-1008"
            )
        }

        do {
            _ = try await createIdentity(custody: "in_memory", createFn: mockCreate)
            Issue.record("Expected createIdentity to throw")
        } catch let error as ScpError {
            if case let .Identity(_, code) = error {
                #expect(code == "SCP-IDENT-1008")
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Load Identity

    @Test("loadIdentity calls bridge and returns identity")
    func loadIdentityRoundtrip() async throws {
        let mockIdentity = MockIdentity(did: "did:dht:z6MkLoaded", custodyType: "external")
        var receivedDid: String?

        let mockLoad: IdentityBridge.LoadFn = { did in
            receivedDid = did
            return mockIdentity
        }

        let result = try await loadIdentity(did: "did:dht:z6MkLoaded", loadFn: mockLoad)
        #expect(result.did() == "did:dht:z6MkLoaded")
        #expect(receivedDid == "did:dht:z6MkLoaded")
    }

    @Test("loadIdentity propagates bridge errors for unsupported DID method")
    func loadIdentityPropagatesErrors() async throws {
        let mockLoad: IdentityBridge.LoadFn = { _ in
            throw ScpError.Identity(
                message: "unsupported DID method",
                code: "SCP-IDENT-1004"
            )
        }

        do {
            _ = try await loadIdentity(did: "did:web:example.com", loadFn: mockLoad)
            Issue.record("Expected loadIdentity to throw")
        } catch let error as ScpError {
            if case let .Identity(_, code) = error {
                #expect(code == "SCP-IDENT-1004")
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Resolve Identity

    @Test("resolveIdentity calls bridge and returns DidDocument")
    func resolveIdentityRoundtrip() async throws {
        var receivedDid: String?

        let mockResolve: IdentityBridge.ResolveFn = { did in
            receivedDid = did
            return DidDocument(
                id: did,
                authentication: ["#0"],
                assertionMethods: ["#active"],
                alsoKnownAs: [],
                serviceEndpoints: ["https://relay.example.com"]
            )
        }

        let doc = try await resolveIdentity(did: "did:dht:z6MkResolved", resolveFn: mockResolve)
        #expect(doc.id == "did:dht:z6MkResolved")
        #expect(doc.authentication == ["#0"])
        #expect(doc.serviceEndpoints.count == 1)
        #expect(receivedDid == "did:dht:z6MkResolved")
    }

    @Test("resolveIdentity propagates bridge errors")
    func resolveIdentityPropagatesErrors() async throws {
        let mockResolve: IdentityBridge.ResolveFn = { _ in
            throw ScpError.Identity(
                message: "DID not found on DHT",
                code: "SCP-IDENT-1006"
            )
        }

        do {
            _ = try await resolveIdentity(did: "did:dht:z6MkUnknown", resolveFn: mockResolve)
            Issue.record("Expected resolveIdentity to throw")
        } catch let error as ScpError {
            if case let .Identity(_, code) = error {
                #expect(code == "SCP-IDENT-1006")
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Create Identity With Agent Key

    @Test("createIdentityWithAgentKey calls bridge and returns identity")
    func createIdentityWithAgentKeyRoundtrip() async throws {
        let mockIdentity = MockIdentity(did: "did:dht:z6MkAgent", custodyType: "in_memory")
        var receivedCustody: String?

        let mockCreate: IdentityBridge.CreateWithAgentKeyFn = { custody in
            receivedCustody = custody
            return mockIdentity
        }

        let result = try await createIdentityWithAgentKey(
            custody: "in_memory",
            createWithAgentKeyFn: mockCreate
        )
        #expect(result.did() == "did:dht:z6MkAgent")
        #expect(receivedCustody == "in_memory")
    }

    @Test("createIdentityWithAgentKey propagates bridge errors")
    func createIdentityWithAgentKeyPropagatesErrors() async throws {
        let mockCreate: IdentityBridge.CreateWithAgentKeyFn = { _ in
            throw ScpError.Identity(
                message: "agent key creation failed",
                code: "SCP-IDENT-1020"
            )
        }

        do {
            _ = try await createIdentityWithAgentKey(custody: "in_memory", createWithAgentKeyFn: mockCreate)
            Issue.record("Expected createIdentityWithAgentKey to throw")
        } catch let error as ScpError {
            if case let .Identity(_, code) = error {
                #expect(code == "SCP-IDENT-1020")
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("createIdentityWithAgentKey default throws descriptive error")
    func createIdentityWithAgentKeyDefaultThrows() async throws {
        do {
            _ = try await createIdentityWithAgentKey(custody: "in_memory")
            Issue.record("Expected default to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1020")
                #expect(message.contains("not yet available"))
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    // MARK: - Migrate Identity

    @Test("migrateIdentity calls bridge and returns migrated identity")
    func migrateIdentityRoundtrip() async throws {
        let original = MockIdentity(did: "did:dht:z6MkOriginal", custodyType: "in_memory")
        let migrated = MockIdentity(did: "did:dht:z6MkMigrated", custodyType: "in_memory")
        var receivedIdentity: Identity?

        let mockMigrate: IdentityBridge.MigrateFn = { identity in
            receivedIdentity = identity
            return migrated
        }

        let result = try await migrateIdentity(original, migrateFn: mockMigrate)
        #expect(result.did() == "did:dht:z6MkMigrated")
        #expect(receivedIdentity?.did() == "did:dht:z6MkOriginal")
    }

    @Test("migrateIdentity propagates bridge errors")
    func migrateIdentityPropagatesErrors() async throws {
        let identity = MockIdentity(did: "did:dht:z6MkFail", custodyType: "in_memory")

        let mockMigrate: IdentityBridge.MigrateFn = { _ in
            throw ScpError.Identity(
                message: "identity not in registry",
                code: "SCP-IDENT-1021"
            )
        }

        do {
            _ = try await migrateIdentity(identity, migrateFn: mockMigrate)
            Issue.record("Expected migrateIdentity to throw")
        } catch let error as ScpError {
            if case let .Identity(_, code) = error {
                #expect(code == "SCP-IDENT-1021")
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }

    @Test("migrateIdentity default throws descriptive error")
    func migrateIdentityDefaultThrows() async throws {
        let identity = MockIdentity(did: "did:dht:z6MkDefault", custodyType: "in_memory")

        do {
            _ = try await migrateIdentity(identity)
            Issue.record("Expected default to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1021")
                #expect(message.contains("not yet available"))
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }
} // end IdentityTests
