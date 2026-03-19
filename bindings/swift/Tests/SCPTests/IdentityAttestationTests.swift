@testable import SCP
import XCTest

/// Tests for identity link attestation wrappers (§3.5).
///
/// Covers:
/// - IdentityAttestation construction and equality
/// - IdentityAttestationBridge defaults throw not-implemented
/// - Public API functions throw not-implemented with correct error codes
/// - IdentityAttestation.verify throws not-implemented
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

    // MARK: - Bridge defaults throw not-implemented

    func testCreateThrowsNotImplemented() async {
        do {
            _ = try await createIdentityAttestation(
                did: "did:dht:z6MkTest",
                platform: "github.com",
                handle: "alice",
                proof: "proof123"
            )
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9010")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testListThrowsNotImplemented() async {
        do {
            _ = try await listIdentityAttestations(did: "did:dht:z6MkTest")
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9011")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testRemoveThrowsNotImplemented() async {
        do {
            _ = try await removeIdentityAttestation(
                did: "did:dht:z6MkTest",
                attestationId: "att-123"
            )
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9012")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    func testVerifyThrowsNotImplemented() async {
        let att = IdentityAttestation(
            id: "abc123",
            platform: "github.com",
            platformHandle: "alice",
            verificationMethod: "did:dht:z6Mk...#active",
            verifiedAt: 1_700_000_000
        )
        do {
            _ = try await att.verify()
            XCTFail("Expected error")
        } catch let error as ScpError {
            switch error {
            case let .Identity(msg, code):
                XCTAssertTrue(msg.contains("not yet available"))
                XCTAssertEqual(code, "SCP-ATTEST-9014")
            default:
                XCTFail("Expected Identity error, got \(error)")
            }
        } catch {
            XCTFail("Unexpected error type: \(error)")
        }
    }

    // MARK: - Custom bridge function injection

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
}
