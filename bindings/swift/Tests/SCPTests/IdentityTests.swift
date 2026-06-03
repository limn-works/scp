@testable import SCP
import XCTest

// Tests for the SDK-level `SCP` identity-registry surface (Batch 4 §4.1).
//
// `identityRemove(did:)` and `identityRemoveIfPresent(did:)` forward to the
// UniFFI bridge, dropping the retained in-memory identity state for a DID.
// These exercise the full create -> remove lifecycle against a real
// `SCP()` instance (the test suite links the Rust binary built with
// `allow_in_memory_custody`).
final class IdentityTests: XCTestCase {
    // Implicitly unwrapped because XCTest `setUp` initializes it before any
    // test method runs — the XCTest lifecycle guarantees non-nil.
    // swiftlint:disable:next implicitly_unwrapped_optional
    var scp: SCP!

    override func setUp() {
        super.setUp()
        scp = SCP()
    }

    override func tearDown() async throws {
        try await scp.shutdown(timeoutMillis: 1000)
        scp = nil
        try await super.tearDown()
    }

    /// Removing an existing identity drops it from the registry; a follow-up
    /// `identityRemoveIfPresent` then reports the DID is gone.
    func testRemoveExistingIdentity() async throws {
        let identity = try await scp.identityCreate(custody: "in_memory")
        let did = identity.did()

        try scp.identityRemove(did: did)
        XCTAssertFalse(
            try scp.identityRemoveIfPresent(did: did),
            "DID must be absent after identityRemove"
        )
    }

    /// `identityRemoveIfPresent` returns `true` for a present DID, then
    /// `false` on the second call once the identity has been removed.
    func testRemoveIfPresentTrueThenFalse() async throws {
        let identity = try await scp.identityCreate(custody: "in_memory")
        let did = identity.did()

        XCTAssertTrue(
            try scp.identityRemoveIfPresent(did: did),
            "first removal must report the identity was present"
        )
        XCTAssertFalse(
            try scp.identityRemoveIfPresent(did: did),
            "second removal must report the identity was already gone"
        )
    }

    /// Removing a DID that was never registered is a silent no-op (for a
    /// syntactically valid DID), matching the cross-bridge `identity_remove`
    /// contract.
    func testRemoveNonexistentIsSilent() throws {
        let missing = "did:dht:z6MkNeverRegisteredIdentityForRemoveTest"
        try scp.identityRemove(did: missing)
        XCTAssertFalse(
            try scp.identityRemoveIfPresent(did: missing),
            "removing an unregistered DID must report false, not throw"
        )
    }

    /// A non-empty but syntactically invalid DID is rejected by both removal
    /// ops via the shared `validate_did` gate, matching the PyO3 reference
    /// bridge and the petname `*RejectsMalformedOwner` parity tests.
    func testRemoveRejectsMalformedDid() {
        let bad = "not-a-did"
        func assertValidation(_ body: () throws -> Void) {
            XCTAssertThrowsError(try body()) { error in
                guard case ScpError.Validation = error else {
                    XCTFail("expected ScpError.Validation, got \(error)")
                    return
                }
            }
        }
        assertValidation { try self.scp.identityRemove(did: bad) }
        assertValidation { _ = try self.scp.identityRemoveIfPresent(did: bad) }
    }
}
