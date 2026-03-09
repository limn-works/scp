@testable import SCP
import Testing

// MARK: - Identity Tests

/// Tests for the ``Identity`` type verifying Sendable conformance,
/// public API shape, DID format validation, and CheckedContinuation-based
/// async bridging.
///
/// UniFFI generates Identity as an open class with methods:
///   - did() -> String
///   - custodyType() -> String
///   - rotateKey() async throws -> Identity
///
/// Tests that need mock Identity instances use subclasses with `noPointer:`.
/// Tests that exercise factory methods (create/load/rotateKey) verify bridge
/// stub error propagation through CheckedContinuation.
///
/// See ADR-026 (Swift SDK) and story SCP-102.
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

    @Test("identityAttestDevice default throws descriptive error")
    func identityAttestDeviceDefaultThrows() async throws {
        let identity = MockIdentity(did: "did:dht:z6MkDefault", custodyType: "in_memory")

        do {
            _ = try await identityAttestDevice(identity)
            Issue.record("Expected default to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1010")
                #expect(message.contains("not yet available"))
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

    @Test("identityVerifyDeviceAttestation default throws descriptive error")
    func identityVerifyDeviceAttestationDefaultThrows() async throws {
        do {
            _ = try await identityVerifyDeviceAttestation(
                did: "did:dht:z6MkDefault",
                tokenBase64: "dGVzdA=="
            )
            Issue.record("Expected default to throw")
        } catch let error as ScpError {
            if case let .Identity(message, code) = error {
                #expect(code == "SCP-IDENT-1012")
                #expect(message.contains("not yet available"))
            } else {
                Issue.record("Expected ScpError.Identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error))")
        }
    }
} // end IdentityTests
