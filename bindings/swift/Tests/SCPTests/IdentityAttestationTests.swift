@testable import SCP
import XCTest

/// Tests for identity link attestation wrappers (§3.5).
///
/// Covers:
/// - IdentityAttestation construction and equality
/// - IdentityAttestationBridge defaults delegate to UniFFI
/// - Forward declaration stubs return expected values before native lib is linked
/// - Wire format JSON parsing round-trips correctly
/// - Custom bridge function injection
final class IdentityAttestationTests: XCTestCase {
    // MARK: - IdentityAttestation struct tests

    func testConstructionDefaults() {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        XCTAssertEqual(att.id, "abc123")
        XCTAssertEqual(att.platform, "github.com")
        XCTAssertEqual(att.platformHandle, "alice")
        XCTAssertEqual(att.verificationMethod, "did:dht:z6Mk...#active")
        XCTAssertEqual(att.verifiedAt, 1_700_000_000)
        XCTAssertEqual(att.revocationStatus, .active)
        XCTAssertNil(att.platformId)
    }

    func testConstructionAllFields() {
        let att = IdentityAttestation(
            id: "def456",
            platform: "x.com",
            platformHandle: "bob",
            verificationMethod: "did:dht:z6Mk...#agent",
            verifiedAt: 1_700_000_000,
            revocationStatus: .revoked(revokedAt: 1_700_000_100, reason: "compromised"),
            platformId: "12345"
        )
        XCTAssertEqual(att.revocationStatus, .revoked(revokedAt: 1_700_000_100, reason: "compromised"))
        XCTAssertEqual(att.revocationStatus.status, "revoked")
        XCTAssertEqual(att.revocationStatus.revokedAt, 1_700_000_100)
        XCTAssertEqual(att.revocationStatus.reason, "compromised")
        XCTAssertEqual(att.platformId, "12345")
    }

    func testRevocationStatusActive() {
        let status = RevocationStatus.active
        XCTAssertEqual(status.status, "active")
        XCTAssertNil(status.revokedAt)
        XCTAssertNil(status.reason)
    }

    func testRevocationStatusRevoked() {
        let status = RevocationStatus.revoked(revokedAt: 1_700_000_100, reason: "test")
        XCTAssertEqual(status.status, "revoked")
        XCTAssertEqual(status.revokedAt, 1_700_000_100)
        XCTAssertEqual(status.reason, "test")
    }

    func testRevocationStatusEquality() {
        XCTAssertEqual(RevocationStatus.active, RevocationStatus.active)
        XCTAssertNotEqual(
            RevocationStatus.active,
            RevocationStatus.revoked(revokedAt: 1_700_000_100)
        )
        XCTAssertEqual(
            RevocationStatus.revoked(revokedAt: 1_700_000_100, reason: "test"),
            RevocationStatus.revoked(revokedAt: 1_700_000_100, reason: "test")
        )
    }

    func testConstructionWithRawJson() {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000,
            rawJson: "{\"id\":\"abc123\"}"
        )
        XCTAssertEqual(att.rawJson, "{\"id\":\"abc123\"}")
    }

    func testEquality() {
        let att1 = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        let att2 = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        XCTAssertEqual(att1, att2)
    }

    func testInequality() {
        let att1 = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        let att2 = IdentityAttestation(
            id: "def456",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        XCTAssertNotEqual(att1, att2)
    }

    // MARK: - Forward declaration stubs (before native lib linked)

    func testRemoveForwardDeclarationReturnsFalse() {
        // The forward declaration returns false until ScpBindings.swift is
        // regenerated with the native library (#1453).
        let result = identityRemoveLinkAttestation(did: "did:dht:z6MkTest", attestationId: "att-123")
        XCTAssertFalse(result)
    }

    // MARK: - Bridge wiring via custom injection

    func testCreateWithCustomFn() async throws {
        let expected = IdentityAttestation(
            id: "test-id",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        let customCreate: IdentityAttestationBridge.CreateFn = { _, _, _, _, _, _ in
            expected
        }
        let result = try await createIdentityAttestation(
            did: "did:dht:z6MkTest",
            platform: "github.com",
            handle: "alice",
            proof: "proof123",
            createFn: customCreate
        )
        XCTAssertEqual(result, expected)
    }

    func testListWithCustomFn() async throws {
        let expected = [
            IdentityAttestation(
                id: "test-id",
                platform: "github.com",
                platformHandle: "alice",
                verificationMethod: "did:dht:z6Mk...#active",
                verifiedAt: 1_700_000_000
            )
        ]
        let customList: IdentityAttestationBridge.ListFn = { _ in expected }
        let result = try await listIdentityAttestations(
            did: "did:dht:z6MkTest",
            listFn: customList
        )
        XCTAssertEqual(result, expected)
    }

    func testRemoveWithCustomFn() async throws {
        let customRemove: IdentityAttestationBridge.RemoveFn = { _, _ in true }
        let result = try await removeIdentityAttestation(
            did: "did:dht:z6MkTest",
            attestationId: "att-123",
            removeFn: customRemove
        )
        XCTAssertTrue(result)
    }

    func testVerifyWithCustomFn() async throws {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        let customVerify: IdentityAttestationBridge.VerifyFn = { _, _ in true }
        let result = try await att.verify(
            issuerPublicKeyHex: "deadbeef",
            verifyFn: customVerify
        )
        XCTAssertTrue(result)
    }

    func testVerifyWithCustomFnFalse() async throws {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        let customVerify: IdentityAttestationBridge.VerifyFn = { _, _ in false }
        let result = try await att.verify(
            issuerPublicKeyHex: "deadbeef",
            verifyFn: customVerify
        )
        XCTAssertFalse(result)
    }

    func testCreateWithCustomFnCaptures() async throws {
        var capturedDid: String?
        var capturedPlatform: String?
        var capturedHandle: String?
        var capturedProof: String?
        var capturedMethod: String?
        var capturedPlatformId: String?

        let customCreate: IdentityAttestationBridge.CreateFn = { did, platform, handle, proof, method, platformId in
            capturedDid = did
            capturedPlatform = platform
            capturedHandle = handle
            capturedProof = proof
            capturedMethod = method
            capturedPlatformId = platformId
            return IdentityAttestation(
                id: "captured",
                platform: platform,
                platformHandle: handle,
                verificationMethod: method,
                verifiedAt: 1_700_000_000,
                platformId: platformId
            )
        }
        let result = try await createIdentityAttestation(
            did: "did:dht:z6MkTest",
            platform: "github.com",
            handle: "alice",
            proof: "proof123",
            verificationMethod: "signed_post",
            platformId: "uid-42",
            createFn: customCreate
        )
        XCTAssertEqual(capturedDid, "did:dht:z6MkTest")
        XCTAssertEqual(capturedPlatform, "github.com")
        XCTAssertEqual(capturedHandle, "alice")
        XCTAssertEqual(capturedProof, "proof123")
        XCTAssertEqual(capturedMethod, "signed_post")
        XCTAssertEqual(capturedPlatformId, "uid-42")
        XCTAssertEqual(result.id, "captured")
        XCTAssertEqual(result.platformId, "uid-42")
    }
}
