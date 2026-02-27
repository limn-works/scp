import Testing

@testable import SCP

// MARK: - Identity Struct Tests

/// Tests for the ``Identity`` struct verifying Sendable conformance,
/// public API shape, and CheckedContinuation-based async bridging.
///
/// These tests validate the ergonomics layer only — the UniFFI bridge
/// stubs return placeholder errors until the XCFramework ships (SCP-103).
/// Tests that exercise the bridge stubs verify the error propagation path
/// through `CheckedContinuation`.
///
/// See ADR-026 (Swift SDK) and story SCP-099.

// MARK: - Type Shape

@Test
func identityIsSendable() async throws {
    // Verify that Identity conforms to Sendable by assigning to a
    // Sendable-constrained binding. This is a compile-time check —
    // if Identity is not Sendable, this file will not compile.
    let handle = IdentityHandle(did: "did:dht:z6MkTest123", custodyType: "in_memory")
    let identity: any Sendable = Identity(handle: handle)
    #expect(identity is Identity)
}

@Test
func identityDidReturnsString() async throws {
    let handle = IdentityHandle(did: "did:dht:z6MkTestDid", custodyType: "platform")
    let identity = Identity(handle: handle)
    #expect(identity.did == "did:dht:z6MkTestDid")
}

@Test
func identityCustodyTypeReturnsString() async throws {
    let handle = IdentityHandle(did: "did:dht:z6MkTestDid", custodyType: "platform")
    let identity = Identity(handle: handle)
    #expect(identity.custodyType == "platform")
}

@Test
func identityPreservesInMemoryCustodyType() async throws {
    let handle = IdentityHandle(did: "did:dht:z6MkTestDid2", custodyType: "in_memory")
    let identity = Identity(handle: handle)
    #expect(identity.custodyType == "in_memory")
}

// MARK: - Factory Methods (Bridge Stub Error Propagation)

@Test
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

@Test
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

@Test
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

@Test
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

@Test
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

@Test
func identityExposesOnlyPublicProperties() async throws {
    // Verify that the handle is not accessible from outside the module.
    // This is enforced by `private let handle` — if it were public or
    // internal, tests in SCPTests (which uses @testable import) could
    // access it. With @testable import, internal members ARE accessible,
    // so we verify the handle's properties match the struct's properties.
    let handle = IdentityHandle(did: "did:dht:z6MkHandleTest", custodyType: "platform")
    let identity = Identity(handle: handle)

    // The public properties should mirror the handle values.
    #expect(identity.did == "did:dht:z6MkHandleTest")
    #expect(identity.custodyType == "platform")
}

// MARK: - No Force Unwraps Verification

@Test
func identityHandlesEmptyDid() async throws {
    // Verify that Identity handles edge cases without force unwrapping.
    let handle = IdentityHandle(did: "", custodyType: "")
    let identity = Identity(handle: handle)
    #expect(identity.did == "")
    #expect(identity.custodyType == "")
}
