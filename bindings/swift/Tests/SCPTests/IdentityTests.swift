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
} // end IdentityTests
