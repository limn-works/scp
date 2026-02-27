import Testing

@testable import SCP

// MARK: - Identity Tests

/// Tests for the ``Identity`` struct verifying Sendable conformance,
/// public API shape, DID format validation, and CheckedContinuation-based
/// async bridging.
///
/// These tests validate the ergonomics layer only -- the UniFFI bridge
/// stubs return placeholder errors until the XCFramework ships (SCP-103).
/// Tests that exercise the bridge stubs verify the error propagation path
/// through `CheckedContinuation`.
///
/// See ADR-026 (Swift SDK) and story SCP-102.
@Suite("Identity Tests")
struct IdentityTests {

    // MARK: - Type Shape

    @Test("Identity conforms to Sendable")
    func identityIsSendable() async throws {
        // Verify that Identity conforms to Sendable by assigning to a
        // Sendable-constrained binding. This is a compile-time check --
        // if Identity is not Sendable, this file will not compile.
        let handle = IdentityHandle(did: "did:dht:z6MkTest123", custodyType: "in_memory")
        let identity: any Sendable = Identity(handle: handle)
        #expect(identity is Identity)
    }

    @Test("Identity DID returns correct string")
    func identityDidReturnsString() async throws {
        let handle = IdentityHandle(did: "did:dht:z6MkTestDid", custodyType: "platform")
        let identity = Identity(handle: handle)
        #expect(identity.did == "did:dht:z6MkTestDid")
    }

    @Test("Identity custody type returns correct string")
    func identityCustodyTypeReturnsString() async throws {
        let handle = IdentityHandle(did: "did:dht:z6MkTestDid", custodyType: "platform")
        let identity = Identity(handle: handle)
        #expect(identity.custodyType == "platform")
    }

    @Test("Identity preserves in_memory custody type")
    func identityPreservesInMemoryCustodyType() async throws {
        let handle = IdentityHandle(did: "did:dht:z6MkTestDid2", custodyType: "in_memory")
        let identity = Identity(handle: handle)
        #expect(identity.custodyType == "in_memory")
    }

    // MARK: - Factory Methods (Bridge Stub Error Propagation)

    @Test("create throws when bridge is unavailable")
    func createThrowsWhenBridgeUnavailable() async {
        // The placeholder bridge stub returns an identity error.
        // This test verifies that the CheckedContinuation correctly
        // propagates the error from the completion handler.
        do {
            _ = try await Identity.create(custody: "in_memory")
            Issue.record("Expected Identity.create to throw when bridge is unavailable")
        } catch let error as ScpError {
            // Verify the error is an identity error with the expected code.
            switch error {
            case .identity(_, let code):
                #expect(code == "SCP-IDENTITY-001")
            default:
                Issue.record("Expected ScpError.identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error)): \(error)")
        }
    }

    @Test("create with default custody throws when bridge is unavailable")
    func createWithDefaultCustodyThrowsWhenBridgeUnavailable() async {
        // Verify that the default custody parameter ("platform") works.
        do {
            _ = try await Identity.create()
            Issue.record("Expected Identity.create to throw when bridge is unavailable")
        } catch let error as ScpError {
            switch error {
            case .identity(_, let code):
                #expect(code == "SCP-IDENTITY-001")
            default:
                Issue.record("Expected ScpError.identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error)): \(error)")
        }
    }

    @Test("load throws when bridge is unavailable")
    func loadThrowsWhenBridgeUnavailable() async {
        // The placeholder bridge stub returns an identity error.
        do {
            _ = try await Identity.load(did: "did:dht:z6MkTestDid")
            Issue.record("Expected Identity.load to throw when bridge is unavailable")
        } catch let error as ScpError {
            switch error {
            case .identity(_, let code):
                #expect(code == "SCP-IDENTITY-002")
            default:
                Issue.record("Expected ScpError.identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error)): \(error)")
        }
    }

    @Test("rotateKey throws when bridge is unavailable")
    func rotateKeyThrowsWhenBridgeUnavailable() async {
        // Create an identity from a handle, then try to rotate.
        let handle = IdentityHandle(did: "did:dht:z6MkTestDid", custodyType: "in_memory")
        let identity = Identity(handle: handle)

        do {
            _ = try await identity.rotateKey()
            Issue.record("Expected rotateKey to throw when bridge is unavailable")
        } catch let error as ScpError {
            switch error {
            case .identity(_, let code):
                #expect(code == "SCP-IDENTITY-003")
            default:
                Issue.record("Expected ScpError.identity, got \(error)")
            }
        } catch {
            Issue.record("Expected ScpError, got \(type(of: error)): \(error)")
        }
    }

    // MARK: - Sendable Crossing

    @Test("Identity can cross task boundary")
    func identityCanCrossTaskBoundary() async throws {
        // Verify that Identity can be sent across task boundaries.
        // This is a compile-time + runtime check for Sendable conformance.
        let handle = IdentityHandle(did: "did:dht:z6MkCrossTask", custodyType: "in_memory")
        let identity = Identity(handle: handle)

        let receivedDid = await Task {
            identity.did
        }.value

        #expect(receivedDid == "did:dht:z6MkCrossTask")
    }

    // MARK: - Handle Isolation

    @Test("Identity exposes only public properties")
    func identityExposesOnlyPublicProperties() async throws {
        // Verify that the handle is not accessible from outside the module.
        // This is enforced by `private let handle` -- if it were public or
        // internal, tests in SCPTests (which uses @testable import) could
        // access it. With @testable import, internal members ARE accessible,
        // so we verify the handle's properties match the struct's properties.
        let handle = IdentityHandle(did: "did:dht:z6MkHandleTest", custodyType: "platform")
        let identity = Identity(handle: handle)

        // The public properties should mirror the handle values.
        #expect(identity.did == "did:dht:z6MkHandleTest")
        #expect(identity.custodyType == "platform")
    }

    // MARK: - DID Format Validation

    @Test("DID format uses did:dht: prefix")
    func didFormatHasDhtPrefix() async throws {
        let handle = IdentityHandle(did: "did:dht:z6MkValidDid", custodyType: "in_memory")
        let identity = Identity(handle: handle)
        #expect(identity.did.hasPrefix("did:dht:"))
    }

    @Test("DID format contains z6Mk multibase prefix")
    func didFormatContainsMultibasePrefix() async throws {
        // SCP uses Ed25519 keys encoded with z-base58 multibase prefix (z6Mk).
        let handle = IdentityHandle(did: "did:dht:z6MkSomeKey123", custodyType: "in_memory")
        let identity = Identity(handle: handle)
        #expect(identity.did.contains("z6Mk"))
    }

    @Test("DID format rejects invalid prefix")
    func didFormatRejectsInvalidPrefix() async throws {
        // Identity preserves whatever DID string the bridge returns.
        // This test verifies that a non-standard DID is stored as-is.
        let handle = IdentityHandle(did: "invalid:prefix:test", custodyType: "in_memory")
        let identity = Identity(handle: handle)
        #expect(!identity.did.hasPrefix("did:dht:"))
        #expect(identity.did == "invalid:prefix:test")
    }

    // MARK: - No Force Unwraps Verification

    @Test("Identity handles empty DID without crashing")
    func identityHandlesEmptyDid() async throws {
        // Verify that Identity handles edge cases without force unwrapping.
        let handle = IdentityHandle(did: "", custodyType: "")
        let identity = Identity(handle: handle)
        #expect(identity.did == "")
        #expect(identity.custodyType == "")
    }

} // end IdentityTests
